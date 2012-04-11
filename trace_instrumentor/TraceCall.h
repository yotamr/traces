/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#include "clang/Rewrite/ASTConsumers.h"
#include "clang/Rewrite/Rewriter.h"
#include "clang/Lex/Lexer.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/AST.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/raw_ostream.h"
#include "../trace_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <string>
#include <iostream>
#include <vector>

#ifndef __TRACE_CALL_H__
#define __TRACE_CALL_H__

using namespace clang;

namespace {

class TraceParam {
public:
    ASTContext &ast;
    Rewriter *Rewrite;
    std::set<const Type *> &referencedTypes;

TraceParam(ASTContext &_ast, Rewriter *rewriter, std::set<const Type *> &_referencedTypes) : ast(_ast), Rewrite(rewriter), referencedTypes(_referencedTypes), type_name("0") { clear(); };
    bool fromType(QualType type, bool fill_unknown);
    bool fromExpr(const Expr *E, bool interpret_char_ptr_as_string);
    unsigned long flags;
    std::string const_str;
    std::string expression;
    std::string size_expression;
    std::string type_name;
    std::string param_name;
    bool is_pointer;
    bool is_reference;
   
    unsigned int size;
    void clear(void) { flags = 0; const_str = std::string(); expression = std::string(); is_pointer = false; is_reference = false;}

    TraceParam& operator = ( const TraceParam& source )
    {
        const_str        = source.const_str;
        param_name       = source.param_name;
        flags            = source.flags;
        expression       = source.expression;
        size_expression  = source.size_expression;
        size             = source.size;
        type_name = type_name;
        is_pointer = is_pointer;
        is_reference = is_reference;
        return *this;
    }
    
    std::string stringifyTraceParamFlags()
    {
        std::stringstream trace_flags;
        trace_flags << "0";
        if (flags & TRACE_PARAM_FLAG_NUM_8) {
            trace_flags << " | TRACE_PARAM_FLAG_NUM_8";
        }
        if (flags & TRACE_PARAM_FLAG_NUM_16) {
            trace_flags << " | TRACE_PARAM_FLAG_NUM_16";
        }
        if (flags & TRACE_PARAM_FLAG_NUM_32) {
            trace_flags << " | TRACE_PARAM_FLAG_NUM_32";
        }
        if (flags & TRACE_PARAM_FLAG_NUM_64) {
            trace_flags << " | TRACE_PARAM_FLAG_NUM_64";
        }
        if (flags & TRACE_PARAM_FLAG_VARRAY) {
            trace_flags << " | TRACE_PARAM_FLAG_VARRAY";
        }
        if (flags & TRACE_PARAM_FLAG_CSTR) {
            trace_flags << " | TRACE_PARAM_FLAG_CSTR";
        }
        if (flags & TRACE_PARAM_FLAG_STR) {
            trace_flags << " | TRACE_PARAM_FLAG_STR";
        }
        if (flags & TRACE_PARAM_FLAG_HEX) {
            trace_flags << " | TRACE_PARAM_FLAG_HEX";
        }
        if (flags & TRACE_PARAM_FLAG_UNSIGNED) {
            trace_flags << " | TRACE_PARAM_FLAG_UNSIGNED";
        }
        if (flags & TRACE_PARAM_FLAG_ZERO) {
            trace_flags << " | TRACE_PARAM_FLAG_ZERO";
        }
        if (flags & TRACE_PARAM_FLAG_ENUM) {
            trace_flags << " | TRACE_PARAM_FLAG_ENUM";
        }
        if (flags & TRACE_PARAM_FLAG_RECORD) {
            trace_flags << " | TRACE_PARAM_FLAG_RECORD";
        }
        if (flags & TRACE_PARAM_FLAG_ENTER) {
            trace_flags << " | TRACE_PARAM_FLAG_ENTER";
        }
        if (flags & TRACE_PARAM_FLAG_LEAVE) {
            trace_flags << " | TRACE_PARAM_FLAG_LEAVE";
        }

        return trace_flags.str();
    }
    
    std::string asString() {
        std::ostringstream os;
        os << "TraceParam(flags = " << stringifyTraceParamFlags() << ", ";
        if (const_str.length() != 0) {
            os << "const_str = \"" << const_str << "\", ";
        }

        if (expression.length() != 0) {
            os << "expression = \"" << expression << "\", ";
        }

        os << "type_name = " << type_name << ")";
        return os.str();
    }

    bool isEnum() {
        if (flags & TRACE_PARAM_FLAG_ENUM) {
            return true;
        } else {
            return false;
        }
    }
    bool isSimple() {
        if (flags & (TRACE_PARAM_FLAG_ENUM | TRACE_PARAM_FLAG_NUM_8 | TRACE_PARAM_FLAG_NUM_16 | TRACE_PARAM_FLAG_NUM_32 | TRACE_PARAM_FLAG_NUM_64) && !(flags & TRACE_PARAM_FLAG_VARRAY)) {
            return true;
        } else {
            return false;
        }
    }

    bool isVarString() {
        if (flags & TRACE_PARAM_FLAG_STR) {
            return true;
        } else {
            return false;
        }
    }

    bool isBuffer() {
        if (flags & TRACE_PARAM_FLAG_VARRAY) {
            return true;
        } else {
            return false;
        }
    }

    void setConstStr(std::string str) {
        flags |= TRACE_PARAM_FLAG_CSTR;
        const_str = str;
    }

private:
    std::string getLiteralString(const CastExpr *expr);
    void referenceType(const Type *type);
    bool parseHexBufParam(const Expr *expr);
    bool parseStringParam(QualType type);
    bool parseStringParam(const Expr *expr);
    bool parseBasicTypeParam(QualType type);
    bool parseBasicTypeParam(const Expr *expr);
    bool parseRecordTypeParam(const Type *expr);
    bool parseRecordTypeParam(const Expr *expr);
    bool parseEnumTypeParam(QualType type);
    bool parseEnumTypeParam(const Expr *expr);
    bool parseClassTypeParam(const Expr *expr);
};

class TraceCall {
public:
TraceCall(llvm::raw_ostream &out, ASTContext &_ast, Rewriter *rewriter, std::set<const Type *> &referenced_types) : ast(_ast), Out(out), Rewrite(rewriter), referencedTypes(referenced_types) { };
    bool fromCallExpr(CallExpr *exp);
    void addTraceParam(TraceParam &param) { args.push_back(param); }
    void setSeverity(enum trace_severity _severity) { severity = _severity; }
    void setKind(const char *_kind) { kind = _kind; }
    std::string getExpansion();
    void expand();
    
private:
    ASTContext &ast;
    llvm::raw_ostream &Out;
    const CallExpr *call_expr;
    std::vector<TraceParam> args;
    enum trace_severity severity;
    const char *kind;
    Rewriter *Rewrite;
    std::set<const Type *> &referencedTypes;
    enum trace_severity functionNameToTraceSeverity(std::string function_name);
    bool parseTraceParams(CallExpr *S, std::vector<TraceParam> &args);
    std::string getLiteralString(const CastExpr *expr);
    void createTraceDeclaration(CallExpr *S, unsigned int severity, std::vector<TraceParam> &args);
    bool prepareSingleTraceParam(const Expr *trace_param, TraceParam &parsed_trace_param);
    void replaceExpr(const Expr *expr, std::string replacement);

    std::string getTypeDefinitionExternDeclratations();
    std::string genMIN(std::string &a, std::string &b);
    std::string commitAndAllocateRecord(enum trace_severity severity);
    std::string getRecord(enum trace_severity severity);
    std::string initializeTypedRecord(enum trace_severity severity);
    std::string commitRecord();
    void unknownTraceParam(const Expr *trace_param);


    std::string getTraceWriteExpression();
    std::string getTraceDeclaration();
};
}

#endif
