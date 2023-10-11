//===-- SimpleStreamChecker.cpp -----------------------------------------*- C++ -*--//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for proper use of fopen/fclose APIs.
//   - If a file has been closed with fclose, it should not be accessed again.
//   Accessing a closed file results in undefined behavior.
//   - If a file was opened with fopen, it must be closed with fclose before
//   the execution ends. Failing to do so results in a resource leak.
//
//===----------------------------------------------------------------------===//




// POSSIBLE IMPROVEMENTS
// 
// Have a function for each Map-Check/Bug Report to minimize code duplication
// Find a way to re-use Bug Visitors to avoid duplication of code
//



#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Analysis/PathDiagnostic.h"
#include "clang/Basic/CharInfo.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/SValExplainer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporterVisitors.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState_Fwd.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TextAPI/Symbol.h"
#include <clang/StaticAnalyzer/Frontend/CheckerRegistry.h>
#include <climits>
#include <ctime>
#include <cwchar>
#include <list>
#include <memory>
#include <string>
#include <utility>

using namespace clang;
using namespace ento;


namespace {

  class GenericErrorCodeChecker;
  using CheckFn = std::function<void(const GenericErrorCodeChecker *, const CallEvent &Call, CheckerContext &C)>;

  //enum ErrCodeKind {NegInt, ConcInt, Nullptr};
  enum ErrorType {NegInt, ConcInt, Nullptr, NotZero};


  // In the mapping from FunctionCall to their respective callback we need to store 
  // additional information. This will be done here.
  struct FnCallback {
    private:
      CheckFn callback;
      int totalArgCount;
      int argToTrack;
      int concreteErrVal;
      ErrorType E;

    public:

      FnCallback(CheckFn callback, int totalArgCount, int argToTrack, int concreteErrVal, ErrorType eck) : callback(callback), totalArgCount(totalArgCount), argToTrack(argToTrack), concreteErrVal(concreteErrVal), E(eck) {}

      bool errCodeIsNegInt() const { return E == NegInt; }
      bool errCodeIsConcInt() const { return E == ConcInt; }
      bool errCodeIsNullptr() const { return E == Nullptr; }

      CheckFn getCallback() const { return callback; }
      int getTotalArgCount() const { return totalArgCount; }
      int getArgToTrack() const { return argToTrack; }
      int getConcErrVal() const { return concreteErrVal; }
      ErrorType getErrorType() const { return E; }
  };



  struct ConcreteIntState {
    private:
      int associatedValue, errorValue;
      ErrorType e;

      ConcreteIntState(int vtt, int ev, ErrorType e) : associatedValue(vtt), errorValue(ev), e(e) {
        // WARNING: Nullptr ist hier eigentlich super useless
        if (e == Nullptr || e == NegInt)
          errorValue = INT_MAX;
      }

    public:
      static ConcreteIntState getNew(int valueToTrack, int errorValue, ErrorType e) {
        return ConcreteIntState(valueToTrack, errorValue, e);
      }

      int getAssociatedValue() const { return associatedValue; }
      int getErrorValue() const { return errorValue; }
      ErrorType getErrorType() const { return e; }

      bool operator==(const ConcreteIntState &cis) const {
        return associatedValue == cis.associatedValue && errorValue == cis.errorValue && e == cis.e;
      }

      void Profile(llvm::FoldingSetNodeID &ID) const  {
        ID.AddInteger(associatedValue);
        ID.AddInteger(errorValue);
        ID.AddInteger(e);
      }
  };


  struct SymRetSymState {
    private:
      SymbolRef associatedSymbol;
      const MemRegion * associatedMemReg;
      int errorValue;
      ErrorType e;

      SymRetSymState(SymbolRef sym, const MemRegion * reg, int ev, ErrorType e) : associatedSymbol(sym), associatedMemReg(reg), errorValue(ev), e(e) {
        if (e == Nullptr || e == NegInt)
          errorValue = INT_MAX;
      }

    public:
      static SymRetSymState getNew(SymbolRef sym, int errorValue, ErrorType e) {
        return SymRetSymState(sym, nullptr, errorValue, e);
      }

      static SymRetSymState getNew(SymRetSymState oldstate, const MemRegion * reg) {
        if (oldstate.getAssociatedMemReg() == nullptr && reg != nullptr)
          return SymRetSymState(oldstate.getAssociatedSymbol(), reg, oldstate.getErrorValue(), oldstate.getErrorType());
        return oldstate;
      }

      SymbolRef getAssociatedSymbol() const { return associatedSymbol; }
      int getErrorValue() const { return errorValue; }
      ErrorType getErrorType() const { return e; }
      const MemRegion * getAssociatedMemReg() const { return associatedMemReg; }


      bool operator==(const SymRetSymState &cis) const {
        return associatedSymbol == cis.associatedSymbol && errorValue == cis.errorValue && e == cis.e && cis.associatedMemReg == associatedMemReg;
      }

      void Profile(llvm::FoldingSetNodeID &ID) const {
        ID.Add(associatedSymbol);
        ID.Add(associatedMemReg);
        ID.AddInteger(errorValue);
        ID.AddInteger(e);
      }
  };


  struct RetSymState {
    private:
      int errorValue;
      const MemRegion * associatedMemReg;
      ErrorType e;

      RetSymState(int ev, const MemRegion * reg, ErrorType e) : errorValue(ev), associatedMemReg(reg), e(e) {
        // WARNING: Nullptr ist hier eigentlich super useless
        if (e == Nullptr || e == NegInt)
          errorValue = INT_MAX;
      }

    public:
      static RetSymState getNew(int errorValue, ErrorType e) {
        return RetSymState(errorValue, nullptr, e);
      }

      static RetSymState getNew(RetSymState oldState, const MemRegion * reg) {
        if (reg && oldState.getAssociatedMemReg() == nullptr)
          return RetSymState(oldState.getErrorValue(), reg, oldState.getErrorType());
        return oldState;
      }

      int getErrorValue() const { return errorValue; }
      const MemRegion * getAssociatedMemReg() const { return associatedMemReg; }
      ErrorType getErrorType() const { return e; }

      bool operator==(const RetSymState &cis) const {
        return errorValue == cis.errorValue && e == cis.e && cis.associatedMemReg == associatedMemReg;
      }

      void Profile(llvm::FoldingSetNodeID &ID) const {
        ID.AddInteger(errorValue);
        ID.Add(associatedMemReg);
        ID.AddInteger(e);
      }
  };
} // end anonymous namespace


// This trait will be used when a function that shall be evaluated without argument
// and the return value is a nonloc::ConcreteInt.
// In the postcall this flag ist set and used in check::Bind
REGISTER_TRAIT_WITH_PROGRAMSTATE(ConcBindAfterCall, bool)
REGISTER_TRAIT_WITH_PROGRAMSTATE(ErrorValueForBind, int)
REGISTER_TRAIT_WITH_PROGRAMSTATE(ErrorTypeForBind, ErrorType)
//REGISTER_TRAIT_WITH_PROGRAMSTATE(CheckRLocInBind, bool)
//
REGISTER_TRAIT_WITH_PROGRAMSTATE(MemRegForBRTrait, bool)

// This Map uses a SymbolRef from an argument as the key and maps onto a structure that contains an int 
REGISTER_MAP_WITH_PROGRAMSTATE(ArgSymToConcIntMap, SymbolRef, ConcreteIntState)

// This Map uses a MemRegion from an argument as the key and maps onto a structure that contains an int
REGISTER_MAP_WITH_PROGRAMSTATE(ArgRegToConcIntMap, const MemRegion *, ConcreteIntState)

// This Map uses a SymbolRef from the return value as the key and maps onto a RetSymState
REGISTER_MAP_WITH_PROGRAMSTATE(RetSymMap, SymbolRef, RetSymState)

// This map uses a SymbolRef from an argument as the key and maps onto a structure that contains another SymbolRef
REGISTER_MAP_WITH_PROGRAMSTATE(ArgSymToRetSymMap, SymbolRef, SymRetSymState)

// This map uses a MemRegion from an argument as the key and maps onto a structure that contains another SymbolRef
REGISTER_MAP_WITH_PROGRAMSTATE(ArgRegToRetSymMap, const MemRegion *, SymRetSymState)

// This Map uses a MemRegion from a return value as the key and maps onto a structure that contains an int
// This works through check::Bind right after a function call.  
REGISTER_MAP_WITH_PROGRAMSTATE(RetRegMap, const MemRegion *, ConcreteIntState)



namespace {

  class GenericErrorCodeChecker : public Checker<check::PostCall, check::PreCall, check::DeadSymbols, check::Bind, check::Location, check::PreStmt<CallExpr>> {

    std::unique_ptr<BugType> ErrValNotCheckedBeforeUseBugType;

    public:

    GenericErrorCodeChecker();

    // Will be used for parsing user input from FunctionsToCheck option
    StringRef functionsToCheck;

    // Will hold all necessary information after parsing
    CallDescriptionMap<FnCallback> CallBackMap = {};


    // Used to make check if the call under question is important to us
    // If so make an entry in one of the MAPs accordingly
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

    // Checks the arguments passed to the call to see if an error has occured
    // If so throw an error
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

    void checkLocation(SVal L, bool isLoad, const Stmt * S, CheckerContext &C) const;

    // If certain symbols are found to be dead this will throw an error.
    // In general this only removes entries from our GDM maps
    void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

    // Mostly necessary to track the RetRegMap successfully. However this is also 
    // important for throwing better Bug reports.
    // This also checks L and R to see if an error may have occured
    void checkBind(SVal L, SVal R, const Stmt * S, CheckerContext &C) const;

    // This function is a remnant that could probably be removed in future revisions
    void reportUseBeforeCheck(SymbolRef Sym, const MemRegion * reg, SourceRange range, CheckerContext &C) const;

    // Necessary for accurate Bug detection. 
    // PreCall already does too much work so that some values arent available anymore
    // Some casting has to be performed but this way all needed values are retrievable
    // ==> May have issues if an argument is casted 
    void checkPreStmt(const CallExpr * CE, CheckerContext &C) const;

    // This helper function tries to resolve an SVal passed to it to a SymbolRef.
    // It uses multiple ways to get to one.
    // Seems to be working well
    ProgramStateRef checkStoreForSVal(SVal loc, ProgramStateRef State, CheckerContext &C, SourceRange SR) const;
  };


  class MyVisitor final : public BugReporterVisitor {
    protected:
      SymbolRef Sym;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.AddPointer(Sym);
      }

      MyVisitor(SymbolRef S ) : Sym(S) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef MyVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const SymRetSymState* TrackedNullab = state->get<ArgSymToRetSymMap>(Sym);
    const SymRetSymState* TrackedNullabPrev = statePrev->get<ArgSymToRetSymMap>(Sym);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev &&
        TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    StringRef Msg;
    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    const MemRegion * reg = TrackedNullab->getAssociatedMemReg();
    if (reg) {
      std::string part1 = "Error value is stored in '";
      part1.append(reg->getDescriptiveName());
      part1.append("' but never checked for errors.");
      Msg = StringRef(part1);

      PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
          N->getFirstPred()->getLocationContext());
      auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
      return P;
    }

    Msg = "Error value can be returned here.";
    StackHint = std::make_unique<StackHintGeneratorForSymbol>(
        TrackedNullab->getAssociatedSymbol(), "Returned error value");

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
  }

  class ArgSymConcIntVisitor final : public BugReporterVisitor {
    protected:
      SymbolRef Sym;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.AddPointer(Sym);
      }

      ArgSymConcIntVisitor(SymbolRef S ) : Sym(S) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef ArgSymConcIntVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const ConcreteIntState * TrackedNullab = state->get<ArgSymToConcIntMap>(Sym);
    const ConcreteIntState * TrackedNullabPrev = statePrev->get<ArgSymToConcIntMap>(Sym);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev &&
        TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    StringRef Msg;
    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    Msg = "Error value can be returned here.";
    StackHint = std::make_unique<StackHintGeneratorForSymbol>(
        Sym, "Returned error value");

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
  }

  class RetSymVisitor final : public BugReporterVisitor {
    protected:
      SymbolRef Sym;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.AddPointer(Sym);
      }

      RetSymVisitor(SymbolRef S ) : Sym(S) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef RetSymVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const RetSymState* TrackedNullab = state->get<RetSymMap>(Sym);
    const RetSymState* TrackedNullabPrev = statePrev->get<RetSymMap>(Sym);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev &&
        TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    StringRef Msg;
    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    const MemRegion * reg = TrackedNullab->getAssociatedMemReg();
    if (reg) {
      std::string part1 = "Error value is stored in '";
      part1.append(reg->getString());
      part1.append("' but never checked for errors.");
      Msg = StringRef(part1);

      PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
          N->getLocationContext());
      auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
      return P;
    }

    Msg = "Error value can be returned here.";
    StackHint = std::make_unique<StackHintGeneratorForSymbol>(
        Sym, "Returned error value");

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
  }

  class MyAssociatedSymVisitor final : public BugReporterVisitor {
    protected:
      SymbolRef Sym;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.AddPointer(Sym);
      }

      MyAssociatedSymVisitor(SymbolRef S ) : Sym(S) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef MyAssociatedSymVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const SymRetSymState* TrackedNullab = state->get<ArgSymToRetSymMap>(Sym);
    const SymRetSymState* TrackedNullabPrev = statePrev->get<ArgSymToRetSymMap>(Sym);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev && TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    StringRef Msg;
    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    Msg = "Error value can be returned here.";
    StackHint = std::make_unique<StackHintGeneratorForSymbol>(
        TrackedNullab->getAssociatedSymbol(), "Returned error value");

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
  }



  class RegToRetSymVisitor final : public BugReporterVisitor {
    protected:
      const MemRegion * reg;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.Add(reg);
      }

      RegToRetSymVisitor(const MemRegion * r ) : reg(r) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef RegToRetSymVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const SymRetSymState* TrackedNullab = state->get<ArgRegToRetSymMap>(reg);
    const SymRetSymState* TrackedNullabPrev = statePrev->get<ArgRegToRetSymMap>(reg);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev && TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }


    StringRef Msg;
    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    const MemRegion * reg = TrackedNullab->getAssociatedMemReg();
    if (reg) {
      std::string part1 = "Error value is stored in '";
      part1.append(reg->getString());
      part1.append("' but never checked for errors.");
      Msg = StringRef(part1);

      PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
          N->getLocationContext());
      auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
      return P;
    }

    Msg = "Error value can be returned here.";
    StackHint = std::make_unique<StackHintGeneratorForSymbol>(
        TrackedNullab->getAssociatedSymbol(), "Returned error value");

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true);
    BR.addCallStackHint(P, std::move(StackHint));
    return P;
  }



  class RetRegVisitor final : public BugReporterVisitor {
    protected:
      const MemRegion * reg;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.Add(reg);
      }

      RetRegVisitor(const MemRegion * r ) : reg(r) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef RetRegVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const ConcreteIntState* TrackedNullab = state->get<RetRegMap>(reg);
    const ConcreteIntState* TrackedNullabPrev = statePrev->get<RetRegMap>(reg);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev && TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    std::string msg = "Error value is stored here";

    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, msg, true);
    return P;
  }

  class ArgRegRetRegVisitor final : public BugReporterVisitor {
    protected:
      const MemRegion * reg;

    public:
      void Profile ( llvm :: FoldingSetNodeID &ID ) const override {
        ID.Add(reg);
      }

      ArgRegRetRegVisitor(const MemRegion * r ) : reg(r) {}

      PathDiagnosticPieceRef VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) override;
  };



  PathDiagnosticPieceRef ArgRegRetRegVisitor::VisitNode(const ExplodedNode* N, BugReporterContext &BRC, PathSensitiveBugReport &BR) {

    ProgramStateRef state = N->getState();
    ProgramStateRef statePrev = N->getFirstPred()->getState();

    const ConcreteIntState* TrackedNullab = state->get<ArgRegToConcIntMap>(reg);
    const ConcreteIntState* TrackedNullabPrev = statePrev->get<ArgRegToConcIntMap>(reg);

    if (!TrackedNullab)
      return nullptr;

    if (TrackedNullabPrev && TrackedNullabPrev == TrackedNullab)
      return nullptr;

    const Stmt* S = N->getStmtForDiagnostics();
    if (!S) { return nullptr; }

    std::string msg = "Error value is stored here";

    std::unique_ptr<StackHintGeneratorForSymbol> StackHint = nullptr;

    PathDiagnosticLocation Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
        N->getLocationContext());
    auto P = std::make_shared<PathDiagnosticEventPiece>(Pos, msg, true);
    return P;
  }


  void GenericErrorCodeChecker::reportUseBeforeCheck(SymbolRef Sym, const MemRegion * reg, SourceRange range, CheckerContext &C) const {
    ExplodedNode* ErrNode = C.generateErrorNode();
    if (!ErrNode)
      return;

    std::string msg;
    if (reg) {
      msg = "Using variable before checking the associated return value in '";
      msg.append(reg->getString());
      msg.append("' for errors.");
    } else {
      msg = "Using variable before checking it's associated return value for errors";
    }

    auto R = std::make_unique<PathSensitiveBugReport>(
        *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
    R->addRange(range);
    if (reg) {
      R->markInteresting(reg);
    }
    R->markInteresting(Sym);
    R->addVisitor(std::make_unique<MyVisitor>(Sym));
    C.emitReport(std::move(R));
  }


  SymbolRef getSValSymbolRef(ProgramStateRef State, SVal s) {
    // DO NOT REMOVE THIS! FOR SOME REASON THIS LEADS TO A CRASH
    // s.dump();

    const MemRegion * R = s.getAsRegion(), *R_old;
    if (R) {
      do {
        const SymbolicRegion *SR = R->getSymbolicBase();
        if (SR) {
          return R->getSymbolicBase()->getSymbol();
        }
        R_old = R;
        R = R->getBaseRegion();
      } while (R != R_old);
    }

    // Attemt to get the SVal as a Loc
    Optional<Loc> tempLoc = s.getAs<Loc>();
    if (!tempLoc) {
      return s.getAsSymbol();
    }

    // Get the binding from the store for the SVal
    SVal tempSVal = State->getStateManager().getStoreManager().getBinding(State->getStore(), tempLoc.getValue());

    // Attemt to cast the SVal to a LazyCompoundVal
    // Necessary for buffers. They are copied lazily. A true copy is only made on change
    Optional<nonloc::LazyCompoundVal> lazyCompVal = tempSVal.getAs<nonloc::LazyCompoundVal>();

    // If the cast worked
    if (lazyCompVal) {
      // Attemt to retrieve the deafult binding for lazyCompVal from the store
      Optional<SVal> lazySVal = State->getStateManager().getStoreManager().getDefaultBinding(lazyCompVal.getValue());

      // If the SVal could be retrieved
      if (lazySVal) { 
        //llvm::errs() << "            SymbolRef from LazyCompund: " << lazySVal.getValue().getAsSymbol() << "\n";
        return lazySVal.getValue().getAsSymbol(); 
      }
    }

    // Another attemt to get a SymbolRef
    SymbolRef argumentSymbol = tempSVal.getAsSymbol();

    // If that also didn't work try the "regular" retrieval method
    if (!argumentSymbol) {
      argumentSymbol = s.getAsSymbol();
      if (argumentSymbol) {
        const MemRegion * originMemRegion = argumentSymbol->getOriginRegion();
        if (originMemRegion) {
          const SymbolicRegion * SR = originMemRegion->getSymbolicBase();
          if (SR) {
            return SR->getSymbol();
          }
        }
      }
      // Return null if nothing worked
      if (!argumentSymbol) { return NULL; }
    }

    return argumentSymbol;
  }

  // This method tries to get a SymbolRef of an argument specified by arg 
  SymbolRef getArgumentSymbolRef(ProgramStateRef State, const CallEvent &Call, int arg) {
    return getSValSymbolRef(State, Call.getArgSVal(arg));
  }


  // This implements the logic behind the error checks.
  // Depending on the ErrorType the corresponding check is performed on sr
  bool symbolCanBeError(SymbolRef sr, int errVal, ErrorType e, CheckerContext &C, ProgramStateRef State) {

    // Get the ConstraintManager. Will be needed for checking the value.
    ConstraintManager &CMgr = State->getConstraintManager();
    SValBuilder &SVB = C.getSValBuilder();

    // sr->dump();
    // llvm::errs() << "    ErrorVal: " << errVal << "\n";

    // What kind of ErrorType do we have to check against
    switch (e) {
      case Nullptr: {
                      // See if the symbol can be NULL
                      ConditionTruthVal Unchecked = CMgr.isNull(State, sr);
                      // If it can still be NULL 
                      if (!Unchecked.isConstrainedFalse()) 
                        return true;
                      break;
                    }
      case ConcInt: {
                      // Make an SVal that compares if sr can be concreteErrVal
                      SVal SymbolCanBeConcInt = SVB.evalBinOp(State, clang::BO_EQ, nonloc::SymbolVal(sr), SVB.makeIntVal(errVal, (sr)->getType()), SVB.getConditionType());

                      Optional<DefinedSVal> DValSymEQ = SymbolCanBeConcInt.getAs<DefinedSVal>();
                      if (!DValSymEQ)
                        break;

                      // If the constructed SVal can be true the Symbol can be the defined error value
                      if (State->assume(*DValSymEQ, true)) {
                        return true;
                      }
                      break;
                    }
      case NegInt: {
                     // Make an SVal that compares if sr can be negative 
                     SVal SymbolCanBeNegative = SVB.evalBinOp(State, clang::BO_LT, nonloc::SymbolVal(sr), SVB.makeIntVal(0, (sr)->getType()), SVB.getConditionType());

                     Optional<DefinedSVal> DValSymLT = SymbolCanBeNegative.getAs<DefinedSVal>();
                     if (!DValSymLT)
                       break;

                     // If the constructed SVal can be true the Symbol can be the defined error value
                     if (State->assume(*DValSymLT, true))
                       return true;
                     break;
                   }
      case NotZero: {
                      SVal SymbolCanNotBeZero = SVB.evalBinOp(State, clang::BO_NE, nonloc::SymbolVal(sr), SVB.makeIntVal(0, (sr)->getType()), SVB.getConditionType());

                      Optional<DefinedSVal> DValSymEQ = SymbolCanNotBeZero.getAs<DefinedSVal>();
                      if (!DValSymEQ)
                        break;

                      // If the constructed SVal can be true the Symbol can be the defined error value
                      if (State->assume(*DValSymEQ, true)) {
                        return true;
                      }
                      break;
                    }
    }
    return false;
  }
} // end anonymous namespace



GenericErrorCodeChecker::GenericErrorCodeChecker() {
  // Initialize the bug types.
  ErrValNotCheckedBeforeUseBugType.reset(
      new BugType(this, "Error value not checked before use.", "Faulty/Missing error handling"));
}

void GenericErrorCodeChecker::checkPreStmt(const CallExpr * CE, CheckerContext &C) const {

  ProgramStateRef State = C.getState();
  State = State->set<MemRegForBRTrait>(false);

  for (Stmt::const_child_iterator I = CE->child_begin(), E = CE->child_end(); I != E; ++I) {
    if (const Stmt * Child = *I) {
      for (Stmt::const_child_iterator I_2 = Child->child_begin(), E_2 = Child->child_end(); I_2 != E_2; ++I_2) {
        if (const Stmt * Child_2 = *I_2) {
          if (const DeclRefExpr * DRE = llvm::dyn_cast<DeclRefExpr>(Child_2)) {
            if (const VarDecl * VD = llvm::dyn_cast<VarDecl>(DRE->getDecl())) {
              Loc lc = C.getStoreManager().getLValueVar(VD, C.getLocationContext());

              std::string msg;
              const MemRegion * region = lc.getAsRegion();
              SVal s = C.getStoreManager().getBinding(C.getState()->getStore(), lc);
              SymbolRef tempSym = s.getAsSymbol();
              if (tempSym) {
                const RetSymState * rsState = State->get<RetSymMap>(tempSym);
                if (rsState) {
                  if (symbolCanBeError(tempSym, rsState->getErrorValue(), rsState->getErrorType(), C, State)) {
                    if (region) {
                      msg = "Variable '";
                      msg.append(region->getString());
                      msg.append("' is used before checking it properly for errors");
                    } else {
                      msg = "Variable is used before checking it properly for errors";
                    }
                    ExplodedNode* ErrNode = C.generateErrorNode();
                    if (ErrNode) {
                      auto R = std::make_unique<PathSensitiveBugReport>(
                          *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
                      R->markInteresting(tempSym);
                      R->addRange(Child_2->getSourceRange());
                      R->addVisitor(std::make_unique<RetSymVisitor>(tempSym));
                      C.emitReport(std::move(R));
                    }
                  }
                  State = State->remove<RetSymMap>(tempSym);
                }
              }

              if (const MemRegion * reg = lc.getAsRegion()) {
                const SymRetSymState * srsState = State->get<ArgRegToRetSymMap>(reg);
                if (srsState) {
                  SymbolRef associatedSym = srsState->getAssociatedSymbol();
                  if (symbolCanBeError(associatedSym, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
                    ExplodedNode* ErrNode = C.generateErrorNode();
                    if (ErrNode) {
                      std::string msg = "Variable '";
                      msg.append(reg->getDescriptiveName(false));
                      msg.append("' is used before checking it's associated return value for erros.");
                      auto BR = std::make_unique<PathSensitiveBugReport>(
                          *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
                      BR->addRange(Child_2->getSourceRange());
                      BR->markInteresting(reg);
                      BR->markInteresting(associatedSym);
                      BR->addVisitor(std::make_unique<RegToRetSymVisitor>(reg));
                      C.emitReport(std::move(BR));
                    }
                  }
                  State = State->remove<ArgRegToRetSymMap>(reg);
                }

                const ConcreteIntState * ciState_2 = State->get<RetRegMap>(reg);
                if(ciState_2) {
                  if (ciState_2->getAssociatedValue() == ciState_2->getErrorValue()) {
                    ExplodedNode* ErrNode = C.generateErrorNode();
                    if (ErrNode) {
                      std::string msg = "Variable '";
                      msg.append(reg->getString());
                      msg.append("' is used before checking it for potential erros.");
                      auto BR = std::make_unique<PathSensitiveBugReport>(
                          *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
                      BR->addRange(Child_2->getSourceRange());
                      BR->addVisitor(std::make_unique<RetRegVisitor>(reg));
                      C.emitReport(std::move(BR));
                    }
                  }
                  State = State->remove<RetRegMap>(reg);
                }
                C.addTransition(State);
              }
            }
          }
        }
      }
    }
  }
}


// Checks a location for errors.
// This was useful for the same reason that check::PreStmt is now being used.
// This Callback may be removed in future revisions as this could all be done in check::PreStmt if errors should only be generated there
void GenericErrorCodeChecker::checkLocation(SVal L, bool isLoad, const Stmt * S, CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  SymbolRef SymRef = getSValSymbolRef(State, L);

  if (SymRef) {
    // If this symbol has an entry in this map, check if an error is possible and if so throw a report 
    const ConcreteIntState * ciState = State->get<ArgSymToConcIntMap>(SymRef);
    if (ciState) {
      if (ciState->getAssociatedValue() == ciState->getErrorValue()) {
        ExplodedNode* ErrNode = C.generateErrorNode();
        if (ErrNode) {
          auto R = std::make_unique<PathSensitiveBugReport>(
              *ErrValNotCheckedBeforeUseBugType, "Using variable before checking it's associated return value for errors", ErrNode);
          R->addRange(S->getSourceRange());
          R->markInteresting(SymRef);
          R->addVisitor(std::make_unique<ArgSymConcIntVisitor>(SymRef));
          C.emitReport(std::move(R));
        }
      }
      State = State->remove<ArgSymToConcIntMap>(SymRef);
    }


    
    // If this symbol has an entry in this map, check if an error is possible and if so throw a report 
    const SymRetSymState * srsState = State->get<ArgSymToRetSymMap>(SymRef);
    if (srsState) {
      SymbolRef associatedSym = srsState->getAssociatedSymbol();
      if (symbolCanBeError(associatedSym, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
        const MemRegion * reg = srsState->getAssociatedMemReg();
        reportUseBeforeCheck(SymRef, reg, S->getSourceRange(), C);
      }
      State = State->remove<ArgSymToRetSymMap>(SymRef);
    }
  }
  C.addTransition(State);
}

// This function attemts to resolve an SVal to a Symbol and then check it for errors and throw a report if an error was found
// If no Symbol could be retrieved try for MemRegions
ProgramStateRef GenericErrorCodeChecker::checkStoreForSVal(SVal loc, ProgramStateRef State, CheckerContext &C, SourceRange SR) const {
  // Attemt to get the SymbolRef for the SVal loc
  SymbolRef SymRef = getSValSymbolRef(State, loc);
  if (SymRef) {
    // If this symbol has an entry in this map, check if an error is possible and if so throw a report 
    const ConcreteIntState * ciState = State->get<ArgSymToConcIntMap>(SymRef);
    if (ciState) {
      if (ciState->getAssociatedValue() == ciState->getErrorValue()) {
        ExplodedNode* ErrNode = C.generateErrorNode();
        if (ErrNode) {
          auto R = std::make_unique<PathSensitiveBugReport>(
              *ErrValNotCheckedBeforeUseBugType, "Using variable before checking it's associated return value for errors", ErrNode);
          R->addRange(SR);
          R->markInteresting(SymRef);
          R->addVisitor(std::make_unique<ArgSymConcIntVisitor>(SymRef));
          C.emitReport(std::move(R));
        }
      }
      State = State->remove<ArgSymToConcIntMap>(SymRef);
    }

    // If this symbol has an entry in this map, check if an error is possible and if so throw a report 
    const RetSymState * rsState = State->get<RetSymMap>(SymRef);
    if (rsState) {
      if (symbolCanBeError(SymRef, rsState->getErrorValue(), rsState->getErrorType(), C, State)) {
        ExplodedNode* ErrNode = C.generateErrorNode();
        if (ErrNode) {
          const MemRegion * reg = rsState->getAssociatedMemReg();
          std::string msg;
          if (reg) {
            msg = "Using variable '";
            msg.append(reg->getString());
            msg.append("' before checking it for errors");
          } else {
            msg = "Using a variable before checking it for errors";
          }
          auto R = std::make_unique<PathSensitiveBugReport>(
              *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
          R->addRange(SR);
          R->markInteresting(SymRef);
          R->addVisitor(std::make_unique<RetSymVisitor>(SymRef));
          C.emitReport(std::move(R));
        }
      }
      State = State->remove<RetSymMap>(SymRef);
    }

    // If this symbol has an entry in this map, check if an error is possible and if so throw a report 
    const SymRetSymState * srsState = State->get<ArgSymToRetSymMap>(SymRef);
    if (srsState) {
      SymbolRef associatedSym = srsState->getAssociatedSymbol();
      if (symbolCanBeError(associatedSym, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
        // Either this is replaced by a Bug report like in all the other cases
        // Or a way is found to make a general bug-report method
        reportUseBeforeCheck(SymRef, srsState->getAssociatedMemReg(), SR, C);
      }
      State = State->remove<ArgSymToRetSymMap>(SymRef);
    }
  }

  // Get the SVal as a MemRegion
  const MemRegion* R = loc.getAsRegion(), *R_old;
  if(R){
    do { 
      // WARNING: REMOVING THIS LINE CAUSES AN ERROR (CHECK WITH AN IF STATEMENT DOES NOT SEEM TO WORK PROPERLY)
      // llvm::errs() << R; 
      
      const ConcreteIntState * ciState = State->get<ArgRegToConcIntMap>(R);
      if (ciState) {
        if (ciState->getAssociatedValue() == ciState->getErrorValue()) {
          ExplodedNode* ErrNode = C.generateErrorNode();
          if (ErrNode) {
            auto BR = std::make_unique<PathSensitiveBugReport>(
                *ErrValNotCheckedBeforeUseBugType, "Using variable before checking it's associated return value for errors", ErrNode);
            BR->addRange(SR);
            BR->addVisitor(std::make_unique<ArgRegRetRegVisitor>(R));
            C.emitReport(std::move(BR));
          }
        }
        State = State->remove<ArgRegToConcIntMap>(R);
      }

      const SymRetSymState * srsState = State->get<ArgRegToRetSymMap>(R);
      if (srsState) {
        SymbolRef associatedSym = srsState->getAssociatedSymbol();
        if (symbolCanBeError(associatedSym, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
          ExplodedNode* ErrNode = C.generateErrorNode();
          if (ErrNode) {
            std::string msg = "Variable '";
            msg.append(R->getDescriptiveName(false));
            msg.append("' is used before checking it's associated return value for erros.");
            auto BR = std::make_unique<PathSensitiveBugReport>(
                *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
            BR->addRange(SR);
            BR->markInteresting(R);
            BR->markInteresting(associatedSym);
            BR->addVisitor(std::make_unique<RegToRetSymVisitor>(R));
            C.emitReport(std::move(BR));
          }
        }
        State = State->remove<ArgRegToRetSymMap>(R);
      }

      const ConcreteIntState * ciState_2 = State->get<RetRegMap>(R);
      if(ciState_2) {
        if (ciState_2->getAssociatedValue() == ciState_2->getErrorValue()) {
          ExplodedNode* ErrNode = C.generateErrorNode();
          if (ErrNode) {
            std::string msg = "Variable '";
            msg.append(R->getString());
            msg.append("' is used before checking it for potential erros.");
            auto BR = std::make_unique<PathSensitiveBugReport>(
                *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
            BR->addRange(SR);
            BR->addVisitor(std::make_unique<RetRegVisitor>(R));
            C.emitReport(std::move(BR));
          }
        }
        State = State->remove<RetRegMap>(R);
      }

      R_old=R;
      R=R->getBaseRegion();
    } while( R != R_old);
  }
  return State;
}



void GenericErrorCodeChecker::checkBind(SVal L, SVal R, const Stmt *S, CheckerContext &C) const {

  ProgramStateRef State = C.getState();

  // Check if L is already tracked and if so throw an error and remove from map
  State = checkStoreForSVal(L, State, C, S->getSourceRange());

  // Absolutely revolting code right here but it works :)
  // Basically gets the first two Children of Stmt S and gets their respective StmtClass
  Stmt::StmtClass firstChildClass, secondChildClass;
  for (Stmt::const_child_iterator I = S->child_begin(), E = S->child_end(); I != E; ++I) {
    if (const Stmt * Child = *I) {
      firstChildClass = Child->getStmtClass();
      for (Stmt::const_child_iterator I2 = Child->child_begin(), E2 = Child->child_end(); I2 != E2; ++I2 ) {
        if (const Stmt * Child2 = *I2) {
          secondChildClass = Child2->getStmtClass();
        }
      }
    }
  }

  // Add a MemRegion to the MAP of a Symbol so that a better Bug Report can be generated
  SymbolRef rhs = getSValSymbolRef(State, R);
  if (rhs) {
    const MemRegion * LR = L.getAsRegion();
    if (LR && State->get<MemRegForBRTrait>()) {
      State = State->set<MemRegForBRTrait>(false);
      ArgSymToRetSymMapTy map = State->get<ArgSymToRetSymMap>();
      for (ArgSymToRetSymMapTy::iterator I = map.begin(), E = map.end(); I != E; ++I) {
        SymbolRef primary = I->first;

        const SymRetSymState  *srsState = State->get<ArgSymToRetSymMap>(primary);
        SymbolRef secondary = srsState->getAssociatedSymbol();

        if (secondary == rhs) {
          State = State->set<ArgSymToRetSymMap>(primary, SymRetSymState::getNew(*srsState, LR));
        }
      }

      RetSymMapTy map_5 = State->get<RetSymMap>();
      for (RetSymMapTy::iterator I = map_5.begin(), E = map_5.end(); I != E; ++I) {
        SymbolRef primary = I->first;
        
        const RetSymState * rsState = State->get<RetSymMap>(primary);
        if (primary == rhs) {
          State = State->set<RetSymMap>(primary, RetSymState::getNew(*rsState, LR));
        }
      }

      ArgRegToRetSymMapTy map_3 = State->get<ArgRegToRetSymMap>(); 
      for (ArgRegToRetSymMapTy::iterator I = map_3.begin(), E = map_3.end(); I != E; ++I) {
        const MemRegion * primary = I->first;

        const SymRetSymState * srsState = State->get<ArgRegToRetSymMap>(primary);
        SymbolRef secondary = srsState->getAssociatedSymbol();
        if (secondary == rhs) {
          State = State->set<ArgRegToRetSymMap>(primary, SymRetSymState::getNew(*srsState, LR));
        }
      }
    }
  }

  // Check if one of the two Children's Class is CallExprClass
  // We Check the first 2 children because the first one may be a cast (like with malloc ==> (char *) malloc(...) )
  if (firstChildClass == Stmt::StmtClass::CallExprClass || secondChildClass == Stmt::StmtClass::CallExprClass) {
    // If the Right side is a CallExpr
    if (State->get<ConcBindAfterCall>()) {
      State = State->set<ConcBindAfterCall>(false);
      const MemRegion * LR = L.getAsRegion();
      if (LR) {
        nonloc::ConcreteInt c = *R.getAs<nonloc::ConcreteInt>();
        int errVal = State->get<ErrorValueForBind>();
        ErrorType e = State->get<ErrorTypeForBind>();

        State = State->set<RetRegMap>(LR, ConcreteIntState::getNew(c.getAsInteger()->getSExtValue(), errVal, e));
      }
    }
    C.addTransition(State);
    return;
  }

  State = checkStoreForSVal(R, State, C, S->getSourceRange());
  State = State->set<ConcBindAfterCall>(false);
  C.addTransition(State);
  return;
}



// This is checks the args of a Fucntion Call to see if an error has occured. For that it uses checkStoreForSVal()
// Also checks if the parent of the CallExpr in the AST is a CompoundStmt. If this is the case this means that the return value
// will not be used in any way and will be discarded. In this case an error can be thrown
void GenericErrorCodeChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {

  ProgramStateRef State = C.getState();
  
  // By default we want this to be false
  State = State->set<ConcBindAfterCall>(false);

  if (!Call.isGlobalCFunction()) {
    C.addTransition(State);
    return;
  }

  unsigned int numArgs = Call.getNumArgs();
  SVal argSVal;
  for (unsigned int i = 0; i < numArgs; i++) {
    argSVal = Call.getArgSVal(i);
    State = checkStoreForSVal(argSVal, State, C, Call.getSourceRange());
  }

  if (const FnCallback * callback = CallBackMap.lookup(Call)) {
    if (const CallExpr * CE = llvm::dyn_cast<CallExpr>(Call.getOriginExpr())) {
      const DynTypedNodeList parent = C.getASTContext().getParents(*CE);
      if (parent.size() == 1) {
        const CompoundStmt * par = parent.begin()->get<CompoundStmt>();
        if (par) {
          ExplodedNode* ErrNode = C.generateErrorNode();
          if (ErrNode) {
            auto R = std::make_unique<PathSensitiveBugReport>(
                *ErrValNotCheckedBeforeUseBugType, "The value returned by this function is not stored or checked anywhere", ErrNode);
            R->addRange(CE->getSourceRange());
            C.emitReport(std::move(R));
          }
        }
      }
    }
  }


  C.addTransition(State);
  return;
}

// This checks if the function under observation is of interest to us
// Depending on the return value and wether an argument is of interest to us we add an entry in one of the maps
void GenericErrorCodeChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  
  // Get the current state so we can modify it later on
  ProgramStateRef State = C.getState();

  if (!Call.isGlobalCFunction())
    return;

  // If the call was to a function specified in the CallBackMap 
  if (const FnCallback * callback = CallBackMap.lookup(Call)) {
    //
    // Get the Return Value as a Symbol and as a nonloc::ConcreteInt 
    SymbolRef returnSymbol = Call.getReturnValue().getAsSymbol();
    Optional<nonloc::ConcreteInt> returnInteger = Call.getReturnValue().getAs<nonloc::ConcreteInt>();

    // If it was possible to get the return value as a nonloc::ConcreteInt
    // Getting the ReturnValue as a MemRegion does not work here
    if (returnInteger) {
      // If there is no argument we need to track further (i.e. we only need to track the return value)
      if (callback->getArgToTrack() == -1) {
        State = State->set<ConcBindAfterCall>(true);
        State = State->set<ErrorValueForBind>(callback->getConcErrVal());
        State = State->set<ErrorTypeForBind>(callback->getErrorType());
        C.addTransition(State);
      } else {
        // Attemt to get a SymbolRef to the important argument we want to track
        SymbolRef argumentSymRef = getArgumentSymbolRef(State, Call, callback->getArgToTrack());
        if (argumentSymRef) {
          // Add to the map (SymbolRef ==> int)
          State = State->set<ArgSymToConcIntMap>(argumentSymRef, ConcreteIntState::getNew(returnInteger->getValue().getSExtValue(), callback->getConcErrVal(), callback->getErrorType()));
          C.addTransition(State);
          return;
        }

        // Attemt to get a MemRegion of the important argument we want to track
        const MemRegion * argumentMemReg = Call.getArgSVal(callback->getArgToTrack()).getAsRegion();
        if (argumentMemReg) {
          // Add to the map (const MemRegion * ==> int)
          State = State->set<ArgRegToConcIntMap>(argumentMemReg, ConcreteIntState::getNew(returnInteger->getValue().getSExtValue(), callback->getConcErrVal(), callback->getErrorType()));
          C.addTransition(State);
          return;
        }

        // If we get to here it will not be possible to track the argument we are interested in
        // Track at least the return value 
        State = State->set<ConcBindAfterCall>(true);
        State = State->set<ErrorValueForBind>(callback->getConcErrVal());
        State = State->set<ErrorTypeForBind>(callback->getErrorType());
        C.addTransition(State);
      }
      return;
    }

    // If the return value was no Symbol either -> abort
    if (!returnSymbol) {
      C.addTransition(State);
      return;
    }

    State = State->set<MemRegForBRTrait>(true);
    // If there is no argument we need to track further (i.e. we only nee to track the return value)
    if (callback->getArgToTrack() == -1) {
      State = State->set<RetSymMap>(returnSymbol, RetSymState::getNew(callback->getConcErrVal(), callback->getErrorType()));
      C.addTransition(State);
    } else {
      // Try to get the SymbolRef to the argument to track
      SymbolRef argSymRef = getArgumentSymbolRef(State, Call, callback->getArgToTrack());
      if (argSymRef) {
        // ADD TO MAP (SymRef ==> SymRef)
        State = State->set<ArgSymToRetSymMap>(argSymRef, SymRetSymState::getNew(returnSymbol, callback->getConcErrVal(), callback->getErrorType()));
        C.addTransition(State);
        return;
      }

      // Attemt to get the Argument as a MemRegion
      const MemRegion * argReg = Call.getArgSVal(callback->getArgToTrack()).getAsRegion();
      if (argReg) {
        State = State->set<ArgRegToRetSymMap>(argReg, SymRetSymState::getNew(returnSymbol, callback->getConcErrVal(), callback->getErrorType()));
        C.addTransition(State);
        return;
      }

      // If we get to here it will not be possible to track the argument we are interested in
      // Track at least the return value
      State = State->set<RetSymMap>(returnSymbol, RetSymState::getNew(callback->getConcErrVal(), callback->getErrorType()));
      C.addTransition(State);
    }
    return;
  }

  C.addTransition(State);
}


// If a Symbol is Dead check to see if this could have caused an error and throw an error.
// Otherwise just remove entries from the GDM Maps on death of a symbol
void GenericErrorCodeChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {
  ProgramStateRef State = C.getState();

  ArgSymToRetSymMapTy map = State->get<ArgSymToRetSymMap>();
  for (ArgSymToRetSymMapTy::iterator I = map.begin(), E = map.end(); I != E; ++I) {
    SymbolRef primary = I->first;

    if (SR.isDead(primary)) {
      // The important argument wont be used in the code anymore so we don't need to track it anymore
      State = State->remove<ArgSymToRetSymMap>(primary);
      continue;
    }

    const SymRetSymState  *srsState = State->get<ArgSymToRetSymMap>(primary);
    SymbolRef secondary = srsState->getAssociatedSymbol();

    // If only the associated (return) symbol is dead
    if (SR.isDead(secondary)) {
      State = State->remove<ArgSymToRetSymMap>(primary);
      // If the secondary symbol can still be the defined error value
      if (symbolCanBeError(secondary, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
        ExplodedNode* ErrNode = C.generateErrorNode();
        if (ErrNode) {
          const MemRegion * reg = srsState->getAssociatedMemReg();
          std::string msg;
          if (reg) {
            msg = "Return value in '";
            msg.append(reg->getString());
            msg.append("' is not checked for errors properly");
          } else {
            msg = "Return value is not properly checked for errors";
          }
          auto R = std::make_unique<PathSensitiveBugReport>(
              *ErrValNotCheckedBeforeUseBugType, msg, ErrNode);
          R->markInteresting(secondary);
          R->addVisitor(std::make_unique<MyVisitor>(primary));
          C.emitReport(std::move(R));
        }
      }
    }
  }

  // Check next map
  // Only remove if dead. Error only happens on first access to the primary (check::Location)
  ArgSymToConcIntMapTy map_2 = State->get<ArgSymToConcIntMap>();
  for (ArgSymToConcIntMapTy::iterator I = map_2.begin(), E = map_2.end(); I != E; ++I) {
    SymbolRef primary = I->first;
    if (SR.isDead(primary)) {
      State = State->remove<ArgSymToConcIntMap>(primary);
    }
  }

  // Check next map 
  ArgRegToRetSymMapTy map_3 = State->get<ArgRegToRetSymMap>(); 
  for (ArgRegToRetSymMapTy::iterator I = map_3.begin(), E = map_3.end(); I != E; ++I) {
    const MemRegion * primary = I->first;

    if (!SR.isLiveRegion(primary)) {
      State = State->remove<ArgRegToRetSymMap>(primary);
      continue;
    }

    const SymRetSymState * srsState = State->get<ArgRegToRetSymMap>(primary);
    SymbolRef secondary = srsState->getAssociatedSymbol();

    if(SR.isDead(secondary)) {
      // If the secondary symbol can still be the defined error value
      if (symbolCanBeError(secondary, srsState->getErrorValue(), srsState->getErrorType(), C, State)) {
        ExplodedNode* ErrNode = C.generateErrorNode();
        if (ErrNode) {
          auto R = std::make_unique<PathSensitiveBugReport>(
              *ErrValNotCheckedBeforeUseBugType, "Return value is not being properly checked for errors. (ArgRegToRetSymMap)", ErrNode);
          R->markInteresting(secondary);
          C.emitReport(std::move(R));
        }
      }
      State = State->remove<ArgRegToRetSymMap>(primary);
    }
  }

  // Check next map
  // Only remove if dead. Error only happens on first access to the primary (check::Location)
  ArgRegToConcIntMapTy map_4 = State->get<ArgRegToConcIntMap>();
  for (ArgRegToConcIntMapTy::iterator I = map_4.begin(), E = map_4.end(); I != E; ++I) {
    const MemRegion * primary = I->first;

    if(!SR.isLiveRegion(primary)) {
      State = State->remove<ArgRegToConcIntMap>(primary);
    }
  }

  // Check next map
  // Only remove if dead. Error only happens on first access to the primary (check::Location)
  RetSymMapTy map_5 = State->get<RetSymMap>();
  for (RetSymMapTy::iterator I = map_5.begin(), E = map_5.end(); I != E; ++I) {
    SymbolRef primary = I->first;
    if (SR.isDead(primary)) {
      State = State->remove<RetSymMap>(primary);
    }
  }

  // Check the last map
  RetRegMapTy map_6 = State->get<RetRegMap>();
  for (RetRegMapTy::iterator I = map_6.begin(), E = map_6.end(); I != E; ++I) {
    const MemRegion * primary = I->first;
    if (!SR.isLiveRegion(primary)) {
      // This is currently not removed as this lead to some errors not being found.
      // Reason unclear
    }
  }
  C.addTransition(State);
}


// Register checker in tree and parse the input list
void registerGenericErrorCodeChecker(CheckerManager &mgr) {
  auto *Checker = mgr.registerChecker<GenericErrorCodeChecker>();
  
  // Read the CheckerOptions and parse them in here
  Checker->functionsToCheck = mgr.getAnalyzerOptions().getCheckerStringOption(Checker, "FunctionsToCheck"); 

  // 2 Delimiters that we need for parsing the input string
  char delimiter1 = ';';
  char delimiter2 = '|';

  // A List made up of pairs made up of CallDescriptions and a FnCallback struct 
  // containing additional information about the CallDescription
  std::list<std::pair<CallDescription, FnCallback>> callDescriptionList;

  // Stop in case the input string is empty
  if (Checker->functionsToCheck.equals("")) {
    llvm::errs() << "Please enter a string of the format functionName|totalArgCount|importantArg|ErrorCode;functionName2|...\n";
    return;
  }

  std::pair<StringRef, StringRef> myPair;
  do
  {
    // myPair will contain one complete description in the first entry
    myPair = Checker->functionsToCheck.split(delimiter1);
    std::pair<StringRef, StringRef> mySecondPair = myPair.first.split(delimiter2);
    StringRef funcName = mySecondPair.first;

    // Read the second entry as an int
    mySecondPair = mySecondPair.second.split(delimiter2);
    int totalArgCount;
    std::sscanf(mySecondPair.first.str().c_str(), "%d", &totalArgCount);

    // Read the third entry as an int and fourth entry as a StringRef into errCode
    mySecondPair = mySecondPair.second.split(delimiter2);
    int importantArg;
    std::sscanf(mySecondPair.first.str().c_str(), "%d", &importantArg);
    StringRef errCode = mySecondPair.second;
    
    ErrorType ECK;
    int concreteIntegerErrVal = INT_MAX; 

    // Set the ECK according to the input
    // If the input is a number concreteIntegerErrVal will be set to that
    if (errCode.equals("NULL")) {
      ECK = Nullptr;
    } else if (errCode.equals("NegInt")) {
      ECK = NegInt;
    } else if (errCode.equals("NotZero")) {
      ECK = NotZero;
    } else {
      ECK = ConcInt;
      std::sscanf(errCode.str().c_str(), "%d", &concreteIntegerErrVal);
    }

    // Now create a FnCallback object with the parsed data
    FnCallback cb = FnCallback(&GenericErrorCodeChecker::checkPostCall, totalArgCount, importantArg, concreteIntegerErrVal, ECK);

    // Create a pair with the CallDescription and the additional data
    std::pair<CallDescription, FnCallback> currentPair = {{funcName.str().c_str(), totalArgCount}, cb};
    
    // Add the pair to our list
    callDescriptionList.push_back(currentPair);

    // Get the rest of the string and continue parsing until no more descriptions are left
    Checker->functionsToCheck = myPair.second;
  } while(myPair.second != "");

  // When we have parsed all input data Create the CallDescriptionMap mapping.
  // Basically this is just a cast from the normal list to this data type for easier handling
  Checker->CallBackMap = CallDescriptionMap<FnCallback>(callDescriptionList.begin(), callDescriptionList.end());
}

// This checker should be enabled regardless of how language options are set.
bool shouldRegisterGenericErrorCodeChecker(const CheckerManager &mgr) {
  return true;
}

// Register plugin!
extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker(
      registerGenericErrorCodeChecker,
      shouldRegisterGenericErrorCodeChecker,
      "alpha.unix.GenericErrorCode",
      "Detects mismatches between memory allocations and deallocations", "",
      false);
  registry.addCheckerOption(
      "String", "alpha.unix.GenericErrorCode", "FunctionsToCheck",
      "", "Function to be checked", "Released", false);
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
