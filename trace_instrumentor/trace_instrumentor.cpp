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

#include "trace_user.h"
#include <stdio.h>
#include <stdlib.h>

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
#include "TraceCall.h"
#include "trace_defs.h"
#include "trace_lib.h"

#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <set>

using namespace clang;

namespace {
static const Type *get_expr_type(const Expr *expr)
{
    return expr->getType().getCanonicalType().split().first;
}

 std::string castTo(LangOptions const& langOpts, std::string orig_expr, std::string cast_type)
 {
     if (langOpts.CPlusPlus == 1) {
         return "reinterpret_cast<" + cast_type + ">(" + orig_expr + ")";
     } else {
         return "(" + cast_type + ") (" + orig_expr + ")";
     }
 }

 std::string & replaceAll(
     std::string &result, 
     const std::string& replaceWhat, 
     const std::string& replaceWithWhat)
 {
     while(1)
     {
         const int pos = result.find(replaceWhat);
         if (pos==-1) break;
         result.replace(pos,replaceWhat.size(),replaceWithWhat);
     }
     return result;
 }
    
static std::string normalizeTypeName(std::string type_str) {
    std::string replaced = replaceAll(type_str, " ", "_");
    return replaceAll(replaced, ":", "_");
}

static std::string getLiteralExpr(ASTContext &ast, Rewriter *Rewrite, const clang::Stmt *S)
{
    SourceManager *SM = &ast.getSourceManager();
    int Size = Rewrite->getRangeSize(S->getSourceRange());
    if (Size == -1) {
        return std::string("");
    }

    const char *startBuf = SM->getCharacterData(S->getLocStart());
    return std::string(startBuf, Size);
}

void hasReturnStmts(Stmt *S, bool &hasReturns) 
{  
  for (Stmt::child_range CI = S->children(); CI; ++CI)
   if (*CI)
     hasReturnStmts(*CI, hasReturns);

 if (isa<ReturnStmt>(S))
   hasReturns = true;
 return;
}


static SourceLocation getReturnStmtEnd(ASTContext &ast, Rewriter *Rewrite, ReturnStmt *S)
{
    const Expr *retValue = S->getRetValue();
    SourceLocation startLoc;
    if (NULL != retValue) {
        startLoc = retValue->getLocStart();
    } else {
        startLoc = S->getLocStart();
    }

    SourceManager *SM = &ast.getSourceManager();
    int Size;
    if (retValue != NULL) {
        Size = Rewrite->getRangeSize(retValue->getSourceRange());
    } else {
        Size = Rewrite->getRangeSize(S->getSourceRange());
    }
    
    const char *startBuf = SM->getCharacterData(startLoc);
    const char *semiBuf = strchr(startBuf + Size, ';');
    assert((*semiBuf == ';') && "getReturnStmtEnd(): can't find ';'");
    return startLoc.getLocWithOffset(semiBuf-startBuf+1);
}

bool TraceParam::parseBasicTypeParam(QualType qual_type)
{
    const Type *type = qual_type.split().first;


    if (type->isReferenceType() || type->isPointerType()) {
        size = ast.getTypeSize(type);
        type_name = qual_type.getAsString();

        if (type->isReferenceType()) {
            is_reference = true;
        } else {
            is_pointer = true;
        }

        flags = TRACE_PARAM_FLAG_HEX;
        if (size == 64) {
            flags |= TRACE_PARAM_FLAG_NUM_64;
        } else {
            flags |= TRACE_PARAM_FLAG_NUM_32;
        }

        size = ast.getTypeSize(type) / 8;
        return true;
    }

    if (!type->isBuiltinType()) {
        return false;
    }

    if (!type->isIntegerType()) {
        return false;
    }

    if (!type->isSignedIntegerType()) {
        flags |= TRACE_PARAM_FLAG_UNSIGNED;
    }

    switch (ast.getTypeSize(type)) {
    case 8:
        flags |= TRACE_PARAM_FLAG_NUM_8;
        break;
    case 16:
        flags |= TRACE_PARAM_FLAG_NUM_16;
        break;
    case 32:
        flags |= TRACE_PARAM_FLAG_NUM_32;
        break;
    case 64:
        flags |= TRACE_PARAM_FLAG_NUM_64;
        break;
    default:
        return false;
    }

    size = ast.getTypeSize(type) / 8;
    type_name = QualType(qual_type.split().first, 0).getAsString();
    if (type_name.compare("_Bool") == 0) {
            type_name = "bool";
    }


    return true;

}

    
bool TraceParam::parseBasicTypeParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreImpCasts();
    
    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    bool parsed = parseBasicTypeParam(expr->getType().getCanonicalType());
    if (!parsed) {
        return false;
    }

    expression = getLiteralExpr(ast, Rewrite, expr);
    return true;
}

void TraceParam::referenceType(const Type *type)
{
    referencedTypes.insert(type);
}

bool TraceParam::parseRecordTypeParam(const Expr *expr)
{
  const Expr *stripped_expr = expr->IgnoreImpCasts();

  const Type *type = get_expr_type(stripped_expr);
  if (NULL == type) {
      return false;
  }
  
  if (!type->isRecordType()) {
      return false;
  }

  referenceType(type);
  flags |= TRACE_PARAM_FLAG_RECORD;
  expression = getLiteralExpr(ast, Rewrite, expr);
  type_name = expr->getType().getCanonicalType().getAsString();
  return true;
}


bool TraceParam::parseEnumTypeParam(QualType qual_type) {
    if (!qual_type.split().first->isEnumeralType()) {
        return false;
    }
    
    referenceType(qual_type.split().first);
    flags |= TRACE_PARAM_FLAG_ENUM;
    type_name = qual_type.getAsString();
    size = 4;
    return true;
}

bool TraceParam::parseEnumTypeParam(const Expr *expr) {
    // Enum's are implicitly cast to ints.
    const Expr *stripped_expr = expr->IgnoreImpCasts();
    
    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    if (!parseEnumTypeParam(stripped_expr->getType().getCanonicalType().getUnqualifiedType())) {
        return false;
    }
    
    expression = getLiteralExpr(ast, Rewrite, expr);

    return true;
}

static bool traceCallReferenced(std::set<TraceCall *> &traces, std::string trace_name)
{
    for (std::set<TraceCall *>::iterator i = traces.begin(); i != traces.end(); i++) {
        TraceCall *trace_call = *i;
        if (trace_call->trace_call_name.compare(trace_name) == 0) {
            return true;
        }
    }

    return false;
}

std::string TraceCall::getTraceDeclaration()
{
    std::stringstream params;
    std::string flags;
    std::string str;
    std::string param_name;
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        param_name = "0";
        flags = param.stringifyTraceParamFlags();
        if (param.param_name.size() > 0) {
            flags += "| TRACE_PARAM_FLAG_NAMED_PARAM";
            param_name = "\"" + param.param_name + "\"";
        }

        if (param.const_str.size() > 0) {
            flags +=  "| TRACE_PARAM_FLAG_CSTR";
            str = "{\"" + param.const_str + "\"}";
        } else {
            std::string type = "0";
            if (param.type_name.compare("0") != 0) {
                str = "{\"" + param.type_name + "\"}";
            }
        }
        
        params << "{" << flags << ", " << param_name << "," << str << "},";
    }

    params << "{0, 0, {0}}";
    std::stringstream descriptor;
    descriptor << "static struct trace_param_descriptor " << trace_call_name << "_params[] = {";
    descriptor << params.str() << "};";
    descriptor << "static struct trace_log_descriptor __attribute__((__section__(\".static_log_data\"))) " << trace_call_name << "= { ";
    descriptor << kind;
    descriptor << + ", " << trace_call_name << "_params };";
    
    return descriptor.str();
}

void TraceCall::replaceExpr(const Expr *expr, std::string replacement)
{
    SourceRange source_range = expr->getSourceRange();
    unsigned int size = Rewrite->getRangeSize(source_range);
    
    Rewrite->ReplaceText(expr->getLocStart(), size, replacement);
}


const char *sev_to_str[] = {"INVALID", "FUNC_TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

std::string TraceCall::constlength_commitRecord()
{
    return "__builtin_memcpy(" + castTo(ast.getLangOptions(), "_record_ptr", "char *") + ", " + castTo(ast.getLangOptions(), "&_record", "char *") + ", sizeof(struct trace_record));";
}

std::string TraceCall::varlength_commitRecord()
{
    return "__builtin_memcpy(" + castTo(ast.getLangOptions(), "(*__record_ptr)", "char *") + ", " + castTo(ast.getLangOptions(), "_record", "char *") + ", sizeof(struct trace_record));";
}

std::string TraceCall::varlength_getRecord(enum trace_severity severity)
{
    std::stringstream code;
    
    code << "(*__record_ptr) = trace_get_record(TRACE_SEV_"  << sev_to_str[severity] << ", &_record->generation);";
    return code.str();
}

std::string TraceCall::constlength_getRecord(enum trace_severity severity)
{
    std::stringstream code;
    
    code << "_record_ptr = trace_get_record(TRACE_SEV_"  << sev_to_str[severity] << ", &_record.generation);";
    return code.str();
}

std::string TraceCall::varlength_initializeTypedRecord(enum trace_severity severity)
{
    std::stringstream code;
    code << "_record->ts = trace_get_nsec();";
    code << "_record->pid = trace_get_pid();";
    code << "_record->tid =  trace_get_tid(); ";
    code << "_record->termination = TRACE_TERMINATION_FIRST;";
    code << "_record->rec_type  = TRACE_REC_TYPE_TYPED;";
    code << "_record->nesting = trace_get_nesting_level();";
    code << "_record->severity = TRACE_SEV_" << sev_to_str[severity] << ";";
    code << "_record->u.typed.log_id = &tracelog - &__static_log_information_start;";
    code << "(*buf_left) = " << TRACE_RECORD_PAYLOAD_SIZE << " - 4;";
    code << "(*typed_buf) += 4;";
    return code.str();
}

std::string TraceCall::constlength_initializeTypedRecord(enum trace_severity severity, unsigned int *buf_left)
{
    std::stringstream code;
    code << "_record.ts = trace_get_nsec();";
    code << "_record.pid = trace_get_pid();";
    code << "_record.tid =  trace_get_tid(); ";
    code << "_record.termination = TRACE_TERMINATION_FIRST;";
    code << "_record.rec_type  = TRACE_REC_TYPE_TYPED;";
    code << "_record.nesting = trace_get_nesting_level();";
    code << "_record.severity = TRACE_SEV_" << sev_to_str[severity] << ";";
    code << "_record.u.typed.log_id = &tracelog - &__static_log_information_start;";
    (*buf_left) = TRACE_RECORD_PAYLOAD_SIZE - 4;
    return code.str();
}

std::string TraceCall::constlength_commitAndAllocateRecord(enum trace_severity severity, unsigned int *buf_left) {
    std::stringstream code;
    code << constlength_commitRecord();
    code << constlength_getRecord(severity);
    code << "_record.termination = 0;";
    (*buf_left) = TRACE_RECORD_PAYLOAD_SIZE;
    return code.str();
}

std::string TraceCall::varlength_commitAndAllocateRecord(enum trace_severity severity) {
    std::stringstream code;
    code << varlength_commitRecord();
    code << varlength_getRecord(severity);
    code << "_record->termination = 0;";
    code << "(*typed_buf) = &_record->u.payload[0];";
    code << "(*buf_left) = " << TRACE_RECORD_PAYLOAD_SIZE << ";";
    return code.str();
}

std::string TraceCall::genMIN(std::string &a, std::string &b)
{
    std::stringstream code;
    code << "((" << a << ")<(" << b << ") ? (" << a << "):(" << b << "))";
    return code.str();
}

std::string TraceCall::varlength_getTraceWriteExpression()
{
    std::stringstream start_record;
     for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];

        if (param.isSimple()) {
            start_record << varlength_writeSimpleValue(param.expression, param.type_name, param.is_pointer, param.is_reference);
        }

        if (param.isVarString()) {
            std::string buf_left_str("(*buf_left) - 1");
            std::string rlen_str("rlen");

            start_record << "{ " << param.type_name << " _s_ = (" << param.expression << ");";
            start_record << "unsigned int rlen = _s_ ? __builtin_strlen(" << castTo(ast.getLangOptions(), "_s_", "const char *") << "): 0;";
            start_record << "do { ";
            start_record << "unsigned int copy_size = " << genMIN(rlen_str, buf_left_str) << ";";
            start_record << "__builtin_memcpy(&((*typed_buf)[1]), _s_, copy_size);";
            start_record << "(*typed_buf)[0] = copy_size;";
            start_record << "(*typed_buf)[0] |= (rlen - copy_size) ? 128 : 0;";
            start_record << "(*typed_buf) += 1 + copy_size;";
            start_record << "rlen -= copy_size;";
            start_record << "(*buf_left) -= copy_size + 1;";
            start_record << "_s_ += copy_size;";
            start_record << "if (rlen || ((*buf_left) == 0)) {";
            start_record << varlength_commitAndAllocateRecord(severity);
            start_record << "}} while (rlen); }";
        }

        if (param.trace_call) {
            if (!traceCallReferenced(globalTraces, param.trace_call->trace_call_name)) {
                globalTraces.insert(param.trace_call);
            }

            // TODO: Just do a single copy
            std::string logid = "(&" + param.trace_call->trace_call_name + "- &__static_log_information_start)";
            std::string _type_name = "int";
            start_record << varlength_writeSimpleValue(logid, _type_name, false, false);
            
            start_record << param.expression;
            start_record << "(buf_left, _record, __record_ptr, typed_buf);";
        }
     }
     
     return start_record.str();
}
    
std::string TraceCall::varlength_getFullTraceWriteExpression()
{
    std::stringstream get_record;
    std::stringstream start_record;
    std::stringstream trace_record_payload;
    get_record << "unsigned int _buf_left; ";
    get_record << "unsigned int *buf_left = &_buf_left; ";
    get_record << "struct trace_record __record;";
    get_record << "struct trace_record *_record = &__record;";
    get_record << "struct trace_record *__record_ptr_alloc;";
    get_record << "struct trace_record **__record_ptr = &__record_ptr_alloc;";
    get_record << "unsigned char *_payload_ptr = " << castTo(ast.getLangOptions(), "&_record->u.payload", "unsigned char *") << ";";
    get_record << "unsigned char **typed_buf =  &_payload_ptr;";
    get_record << varlength_getRecord(severity);
    start_record << varlength_initializeTypedRecord(severity);
    start_record << varlength_getTraceWriteExpression();
    start_record << "_record->termination |= TRACE_TERMINATION_LAST;";
    start_record << varlength_commitRecord();

    return get_record.str() + start_record.str();
}

std::string TraceCall::constlength_getFullTraceWriteExpression()
{
    std::stringstream get_record;
    std::stringstream start_record;
    std::stringstream trace_record_payload;
    unsigned int buf_left = 0;
    get_record << "struct trace_record _record;";
    get_record << "struct trace_record *_record_ptr;";
    get_record << constlength_getRecord(severity);
    start_record << constlength_initializeTypedRecord(severity, &buf_left);
    start_record << constlength_getTraceWriteExpression(&buf_left);
    start_record << "_record.termination |= TRACE_TERMINATION_LAST;";
    start_record << constlength_commitRecord();

    return get_record.str() + start_record.str();
}

    
std::string TraceCall::constlength_writeSimpleValue(std::string &expression, std::string &type_name, bool is_pointer, bool is_reference, unsigned int value_size, unsigned int *buf_left)
{
    std::stringstream serialized;

    serialized << "{";
    if (is_pointer) {
        serialized << "volatile const void * __src__ =  " << castTo(ast.getLangOptions(), expression, "volatile const void *") << ";";
    } else if (is_reference) {
        serialized << "volatile const void * __src__ =  " << castTo(ast.getLangOptions(), "&" + expression, "volatile const void *") << ";";
    } else {
        serialized << type_name <<  " __src__ = (" << expression << ");";
    }
    
    unsigned int copy_size = MIN(value_size, (*buf_left));
    serialized << "__builtin_memcpy((&_record.u.payload[" << TRACE_RECORD_PAYLOAD_SIZE - (*buf_left) << "]), &__src__," << copy_size << ");";
    (*buf_left) -= copy_size;
    if ((*buf_left) == 0) {
        if (copy_size) {
            serialized << constlength_commitAndAllocateRecord(severity, buf_left);
            serialized << "__builtin_memcpy(&_record.u.payload, " + castTo(ast.getLangOptions(), "(&__src__", "const char *") << "+ " << copy_size << "), " << value_size - copy_size << ");";
        }
        
        (*buf_left) -= value_size - copy_size;
    }

    serialized << "}";
    return serialized.str();
}
    
std::string TraceCall::varlength_writeSimpleValue(std::string &expression, std::string &type_name, bool is_pointer, bool is_reference)
{
    std::stringstream serialized;
    std::string expression_sizeof = "sizeof(__src__)";
    std::string buf_left_str = "(*buf_left)";

    serialized << "{";
    if (is_pointer) {
        serialized << "volatile const void * __src__ =  " << castTo(ast.getLangOptions(), expression, "volatile const void *") << ";";
    } else if (is_reference) {
        serialized << "volatile const void * __src__ =  " << castTo(ast.getLangOptions(), "&" + expression, "volatile const void *") << ";";
    } else {
        serialized << type_name <<  " __src__ = (" << expression << ");";
    }
    
    serialized << "unsigned int copy_size = " << genMIN(expression_sizeof, buf_left_str) << ";";
    serialized << "__builtin_memcpy((*typed_buf), &__src__, copy_size);";
    
    serialized << "(*typed_buf) += copy_size;";
    serialized << "(*buf_left) -= copy_size;";
    serialized << "if ((*buf_left) == 0) {";
    serialized << varlength_commitAndAllocateRecord(severity);
    serialized << "__builtin_memcpy((*typed_buf), " + castTo(ast.getLangOptions(), "&__src__", "const char *") + "+ copy_size, sizeof(__src__) - copy_size);";
    serialized << "(*typed_buf) += " << expression_sizeof << " - copy_size;";
    serialized << "(*buf_left) -= " << expression_sizeof << " - copy_size;";
    serialized << "}}";

    return serialized.str();
}

std::string TraceCall::constlength_getTraceWriteExpression(unsigned int *buf_left)
{
    std::stringstream start_record;
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        
        if (param.isSimple()) {
            start_record << constlength_writeSimpleValue(param.expression, param.type_name, param.is_pointer, param.is_reference, param.size, buf_left);
        }

    }

    return start_record.str();
}

std::string TraceCall::getExpansion() {
    if (constantSizeTrace()) {
        return getTraceDeclaration() + constlength_getFullTraceWriteExpression();
    } else {
        return getTraceDeclaration() + varlength_getFullTraceWriteExpression();
    }
}

void TraceCall::expand()
{
    std::string declaration = getTraceDeclaration();
    std::string trace_write_expression = varlength_getFullTraceWriteExpression();
    replaceExpr(call_expr, "{" + declaration + "if (current_trace_buffer != 0){"  + trace_write_expression + "}}");    
}

void TraceCall::expandWithoutDeclaration()
{
    std::string trace_write_expression = varlength_getTraceWriteExpression();
    replaceExpr(call_expr, "if (current_trace_buffer != 0){"  + trace_write_expression + "}");    
}


class FunctionCallerFinder : public StmtVisitor<FunctionCallerFinder> {
    unsigned int call_count;
    CallExpr *CE;
    std::string function_name;
public:
    void VisitCallExpr(CallExpr* _CE) {
        const FunctionDecl *callee = _CE->getDirectCallee();
        if (function_name.compare(callee->getNameAsString()) == 0) {
            call_count++;
            CE = _CE;
        }
    }

    void VisitStmt(Stmt* stmt) {
        Stmt::child_iterator CI, CE = stmt->child_end();
        for (CI = stmt->child_begin(); CI != CE; ++CI) {
            if (*CI != 0) {
                Visit(*CI);
            }
        }
    }

    CallExpr *functionHasFunctionCall(Stmt *body, std::string _function_name, int *_call_count) {
        function_name = _function_name;
        CE = NULL;
        call_count = 0;
        Visit(body);
        *_call_count = call_count;
        return CE;
    }
};

class StructFinder : public DeclVisitor<StructFinder> {
    RecordDecl *RD;
    std::string decl_name;
public:
    
    void VisitRecordDecl(RecordDecl* _RD) {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = _RD;
            }
        }
    }

    void VisitLinkageSpecDecl(LinkageSpecDecl *D) {
        if (D->hasBraces()) {
            VisitDeclContext(D);
        } else {
            Visit(*D->decls_begin());
        }

    }

    void VisitNamespaceDecl(NamespaceDecl *D) {
        VisitDeclContext(D);
    }

    void VisitCXXRecordDecl(CXXRecordDecl *_RD) {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = dyn_cast<RecordDecl>(_RD);
            }
        }
    }

    void VisitEnumDecl(EnumDecl *D) {
        if (D->isCompleteDefinition()) {
            VisitDeclContext(D);
        }
    }

    void VisitDeclContext(DeclContext *DC) {
        for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end();
             D != DEnd; ++D) {
            Visit(*D);
        }
    }

    void VisitTranslationUnitDecl(TranslationUnitDecl *D) {
        VisitDeclContext(D);
    }

    RecordDecl *findDeclByName(Decl *body, std::string _decl_name) {
        decl_name = _decl_name;
        RD = NULL;
        Visit(body);
        return RD;
    }
};

bool TraceParam::parseClassTypeParam(const Expr *expr)
{
    const Type *type = expr->getType().getTypePtr();


    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().first;
    if (!pointeeType->isClassType()) {
        return false;
    }


    CXXRecordDecl *RD = cast<CXXRecordDecl>(pointeeType->getAs<RecordType>()->getDecl());
    CXXMethodDecl *MD = NULL;
    for (CXXRecordDecl::method_iterator method = RD->method_begin();
         method != RD->method_end();
         ++method) {
        if (method->getNameAsString().compare("_trace_represent") == 0) {
            if (!method->hasInlineBody()) {
                Diags.Report(ast.getFullLoc(method->getLocStart()), NonInlineTraceRepresentDiag) << method->getSourceRange();
                return false;
            }

            MD = *method;
            break;
        }
    }

    if (NULL == MD) {
        return false;
    }

    FunctionCallerFinder finder;
    int call_count;
    CallExpr *call_expr = finder.functionHasFunctionCall(MD->getBody(), "REPR", &call_count);
    if (call_expr == NULL) {
        return false;
    }

    if (call_count > 1) {
        Diags.Report(ast.getFullLoc(call_expr->getLocStart()), MultipleReprCallsDiag) << call_expr->getSourceRange();
    }
    
    TraceCall *_trace_call = new TraceCall(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    if (!_trace_call->fromCallExpr(call_expr)) {
        return false;
    }

    trace_call = _trace_call;
    // TODO: Unique name, don't add duplicate logs
    std::string _type_name = normalizeTypeName(QualType(pointeeType, 0).getAsString());
    std::stringstream trace_call_name;
    trace_call_name << _type_name;
    trace_call_name << "_tracelog";
    trace_call->trace_call_name = trace_call_name.str();
    method_generated =  true;
    flags |= TRACE_PARAM_FLAG_NESTED_LOG;
    expression = "(" + getLiteralExpr(ast, Rewrite, expr) + ")->_trace_represent";
    type_name = QualType(pointeeType, 0).getAsString();

    return true;    
}

bool TraceParam::parseHexBufParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreParens();
    if (!isa<CStyleCastExpr>(stripped_expr)) {
        return false;
    }

    const Type *type = stripped_expr->getType().getTypePtr();
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().IgnoreParens().getTypePtr();
    if (pointeeType->getTypeClass() != Type::VariableArray && pointeeType->getTypeClass() != Type::ConstantArray) {
        return false;
    }

    const ArrayType *A = dyn_cast<ArrayType>(pointeeType);
    if (A->getElementType().split().first->getTypeClass() != Type::Typedef) {
        return false;
    }

    const TypedefType *TDP = dyn_cast<TypedefType>(A->getElementType().split().first);
    const TypedefNameDecl *decl = TDP->getDecl();
    if (decl->getDeclName().getAsString().compare("hex_t") != 0) {
        return false;
    }

    flags |= TRACE_PARAM_FLAG_UNSIGNED | TRACE_PARAM_FLAG_VARRAY | TRACE_PARAM_FLAG_NUM_8 | TRACE_PARAM_FLAG_HEX;
   
    if (isa<VariableArrayType>(A)) {
        const VariableArrayType *VAT = dyn_cast<VariableArrayType>(A);
        size_expression = getLiteralExpr(ast, Rewrite, VAT->getSizeExpr());
    } else if (isa<ConstantArrayType>(A)) {
        const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(A);
        size = CAT->getSize().getZExtValue();
    }

    expression = getLiteralExpr(ast, Rewrite, expr);
    
    return true;
}
        
std::string TraceParam::getLiteralString(const Expr *expr)
{
    std::string empty_string;
    if (!isa<StringLiteral>(expr)) {
        return empty_string;
    }

    const StringLiteral *string_literal = dyn_cast<StringLiteral>(expr);
    return string_literal->getString();
}

bool TraceParam::parseStringParam(QualType qual_type)
{
    const Type *type = qual_type.split().first;
    if (!type->isPointerType()) {
        return false;
    }
    
    const Type *pointeeType = type->getPointeeType().split().first;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    type_name = qual_type.getAsString();
    return true;
}

bool TraceParam::parseStringParam(const Expr *expr)
{
    const Type *type = get_expr_type(expr);
    if (NULL == type) {
        return false;
    }
    if (!type->isPointerType()) {
        return false;
    }
    
    const Type *pointeeType = type->getPointeeType().split().first;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    const Expr *stripped_expr = expr->IgnoreImpCasts();
    if (isa<StringLiteral>(stripped_expr)) {
        std::string literalString = getLiteralString(stripped_expr);
        if (literalString.length() != 0) {
            type_name = expr->getType().getCanonicalType().getAsString();
            const_str = literalString;
            return true;
        } else {
            Diags.Report(ast.getFullLoc(stripped_expr->getLocStart()), EmptyLiteralStringDiag) << stripped_expr->getSourceRange();
            return false;
        }
    }

    std::string stringExpression = getLiteralExpr(ast, Rewrite, expr);
    if (stringExpression.length() != 0) {
        expression = stringExpression;
        flags |= TRACE_PARAM_FLAG_STR | TRACE_PARAM_FLAG_VARRAY;
        type_name = expr->getType().getCanonicalType().getAsString();
        return true;
    }

    return false;
}

void TraceCall::unknownTraceParam(const Expr *trace_param)
{
    Diags.Report(ast.getFullLoc(trace_param->getLocStart()), UnknownTraceParamDiag) << trace_param->getSourceRange();
}

static std::string getCallExprFunctionName(const CallExpr *CE)
{
    const FunctionDecl *callee = CE->getDirectCallee();
    if (NULL == callee) {
        return std::string();
    }
    
    return callee->getQualifiedNameAsString();    
}

enum trace_severity TraceCall::functionNameToTraceSeverity(std::string function_name)
{
    return trace_function_name_to_severity(function_name.c_str());
}

bool TraceParam::fromType(QualType type, bool fill_unknown_type) {
    QualType canonical_type = type.getCanonicalType();
    if (parseEnumTypeParam(canonical_type)) {
        return true;
    } else if (parseBasicTypeParam(canonical_type)) {
        return true;
    }

    if (fill_unknown_type) {
        const_str = "...";
        return true;
    } else {
        return false;
    }
}

bool TraceParam::fromExpr(const Expr *trace_param, bool deref_pointer)
{
    if (deref_pointer && parseStringParam(trace_param)) {
        return true; 
    } else if (parseHexBufParam(trace_param)) {
        return true;
    } else if (parseEnumTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseRecordTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseClassTypeParam(trace_param)) {
        return true;
    } else if (parseBasicTypeParam(trace_param)) {
        return true;
    }

    return false;
}

static bool valid_param_name(std::string &name)
{
    const char *ptr = name.c_str();
    if (isdigit(*ptr) || ispunct(*ptr)) {
        return false;
    }
    
    while (*ptr) {
        char c = *ptr;
        if (!isalnum(c) && c != '_') {
            return false;
        }
        ptr++;
    }

    return true;
}

bool TraceCall::constantSizeTrace(void)
{
    for (unsigned int i = 0; i < args.size(); i++) {
        TraceParam &param = args[i];
        if (param.isVarString()) {
            return false;
        }

        if (param.trace_call) {
            return false;
        }
    }

    return true;
}

bool TraceCall::parseTraceParams(CallExpr *S, std::vector<TraceParam> &args)
{
    Expr **call_args = S->getArgs();
    for (unsigned int i = 0; i < S->getNumArgs(); i++) {
        TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        trace_param.clear();
        if (trace_param.fromExpr(call_args[i], true)) {
            if (trace_param.const_str.length() == 0 && valid_param_name(trace_param.expression)) {
                trace_param.param_name = trace_param.expression;
            }
            
            args.push_back(trace_param);
        } else {
            unknownTraceParam(call_args[i]);
            return false;
        }
    }

    return true;
}
    
bool TraceCall::fromCallExpr(CallExpr *expr) {
    args.clear();
    severity = TRACE_SEV_INVALID;
    std::string function_name = getCallExprFunctionName(expr);
    enum trace_severity _severity = functionNameToTraceSeverity(function_name);
    if ((_severity < TRACE_SEV__MIN || _severity > TRACE_SEV__MAX)) {
        if (function_name.compare("REPR") != 0) {
            return false;
        }
    }

    severity = _severity;
    kind = "TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT";
    if(!parseTraceParams(expr, args)) {
        return false;
    }

    call_expr = expr;
    return true;
}

class DeclIterator : public DeclVisitor<DeclIterator> {
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;

    DeclIterator(llvm::raw_ostream& xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter, SourceManager *sm, const LangOptions &_langOpts, std::set<const Type *> &referenced_types, std::set<TraceCall *> &global_traces) : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), referencedTypes(referenced_types), globalTraces(global_traces)  {};
    void VisitDeclContext(DeclContext *DC, bool Indent = true);
    void VisitTranslationUnitDecl(TranslationUnitDecl *D);
    void VisitTypedefDecl(TypedefDecl *D);
    void VisitTypeAliasDecl(TypeAliasDecl *D);
    void VisitEnumDecl(EnumDecl *D);
    void VisitRecordDecl(RecordDecl *D);
    void VisitEnumConstantDecl(EnumConstantDecl *D);
    void VisitFunctionDecl(FunctionDecl *D);
    void VisitFieldDecl(FieldDecl *D);
    void VisitVarDecl(VarDecl *D);
    void VisitLabelDecl(LabelDecl *D);
    void VisitParmVarDecl(ParmVarDecl *D);
    void VisitFileScopeAsmDecl(FileScopeAsmDecl *D);
    void VisitStaticAssertDecl(StaticAssertDecl *D);
    void VisitNamespaceDecl(NamespaceDecl *D);
    void VisitUsingDirectiveDecl(UsingDirectiveDecl *D);
    void VisitNamespaceAliasDecl(NamespaceAliasDecl *D);
    void VisitCXXRecordDecl(CXXRecordDecl *D);
    void VisitLinkageSpecDecl(LinkageSpecDecl *D);
    void VisitTemplateDecl(const TemplateDecl *D);
    void VisitFunctionTemplateDecl(FunctionTemplateDecl *D);
    void VisitClassTemplateDecl(ClassTemplateDecl *D);

private:
    SourceLocation getFunctionBodyStart(Stmt *FB);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;
};

class StmtIterator : public StmtVisitor<StmtIterator> {
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    Decl *D;

    StmtIterator(llvm::raw_ostream& xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter, SourceManager *sm, const LangOptions &_langOpts, Decl *_D, std::set<const Type *>&referenced_types, std::set<TraceCall *> &global_traces) : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), D(_D), referencedTypes(referenced_types), globalTraces(global_traces)  {};

#define STMT(Node, Base) void Visit##Node(Node *S);
#include <clang/AST/StmtNodes.inc>

    void VisitStmt(Stmt *S);
    void VisitDecl(Decl *D);
    void VisitType(QualType T);
    void VisitName(DeclarationName Name);
    void VisitNestedNameSpecifier(NestedNameSpecifier *NNS);
    void VisitTemplateName(TemplateName Name);
    void VisitTemplateArguments(const TemplateArgumentLoc *Args, unsigned NumArgs);
    void VisitTemplateArgument(const TemplateArgument &Arg);

private:
    void expandTraceLog(unsigned int severity, CallExpr *S);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;

};


void DeclIterator::VisitDeclContext(DeclContext *DC, bool Indent) {
  for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end();
       D != DEnd; ++D) {
      Visit(*D);
  }
}

void DeclIterator::VisitTranslationUnitDecl(TranslationUnitDecl *D) {
    VisitDeclContext(D, false);
}

void DeclIterator::VisitTypedefDecl(TypedefDecl *D) {
}

void DeclIterator::VisitTypeAliasDecl(TypeAliasDecl *D) {
}

void DeclIterator::VisitEnumDecl(EnumDecl *D) {
  if (D->isCompleteDefinition()) {
      VisitDeclContext(D);
  }
}

void DeclIterator::VisitRecordDecl(RecordDecl *D) {
  if (D->isCompleteDefinition()) {
      VisitDeclContext(D);
  }
}

void DeclIterator::VisitEnumConstantDecl(EnumConstantDecl *D) {
}

SourceLocation DeclIterator::getFunctionBodyStart(Stmt *FB)
{
    SourceLocation startLoc;
    startLoc = FB->getLocStart();
    
    return startLoc.getLocWithOffset(1);
}
    
void DeclIterator::VisitFunctionDecl(FunctionDecl *D) {

    if (NULL != strstr(D->getQualifiedNameAsString().c_str(), "std::")) {
        return;
    }
    
    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return;
        }
    }
    
    if (!(D->hasBody()  &&  D->isThisDeclarationADefinition())) {
        return;
    }
    StmtIterator stmtiterator(Out, Diags, ast, Rewrite, SM, langOpts, D, referencedTypes, globalTraces);

    bool has_returns = false;
    Stmt *stmt = D->getBody();
    SourceLocation function_start = getFunctionBodyStart(stmt);
    TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(D->getQualifiedNameAsString());
    TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    trace_call.addTraceParam(function_name_param);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;


    if (NULL != strstr(D->getQualifiedNameAsString().c_str(), "_trace_represent")) {
        goto exit;
    }
    
    trace_call.setSeverity(severity);
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY");
    if (D->hasAttr<NoInstrumentFunctionAttr>() || D->isInlined() || D->isInlineSpecified()) {
        goto exit;
    }

    hasReturnStmts(stmt, has_returns);
    if (!has_returns || D->getResultType()->isVoidType()) {
        SourceLocation endLocation = stmt->getLocEnd();
        TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);

        function_name_param.setConstStr(D->getQualifiedNameAsString());
    
        TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
        trace_call.setSeverity(severity);
        trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
        trace_call.addTraceParam(function_name_param);
        Rewrite->ReplaceText(endLocation, 1, "{if (current_trace_buffer != 0) {trace_decrement_nesting_level(); " + trace_call.getExpansion() + "}}}");
    }
    
    for (FunctionDecl::param_const_iterator I = D->param_begin(),
             E = D->param_end(); I != E; ++I) {
        trace_param.clear();
        if ((*I)->getNameAsString().length() == 0) {
            continue;
        }
        bool was_parsed = trace_param.fromType((*I)->getType().getCanonicalType(), true);
        if (!was_parsed) {
            stmtiterator.Visit(D->getBody());
            return;
        }

        trace_param.param_name = (*I)->getNameAsString();
        trace_param.expression = (*I)->getNameAsString();
        trace_call.addTraceParam(trace_param);
    }


    Rewrite->InsertText(function_start, "if (current_trace_buffer != 0){" + trace_call.getExpansion() + "trace_increment_nesting_level();}", true);
exit:
    stmtiterator.Visit(D->getBody());
}

void DeclIterator::VisitFieldDecl(FieldDecl *D) {
}

void DeclIterator::VisitLabelDecl(LabelDecl *D) {
}


void DeclIterator::VisitVarDecl(VarDecl *D) {
}

void DeclIterator::VisitParmVarDecl(ParmVarDecl *D) {
    VisitVarDecl(D);
}

void DeclIterator::VisitFileScopeAsmDecl(FileScopeAsmDecl *D) {
}

void DeclIterator::VisitStaticAssertDecl(StaticAssertDecl *D) {
}


//----------------------------------------------------------------------------
// C++ declarations
//----------------------------------------------------------------------------
void DeclIterator::VisitNamespaceDecl(NamespaceDecl *D) {
    VisitDeclContext(D);
}

void DeclIterator::VisitUsingDirectiveDecl(UsingDirectiveDecl *D) {
}

void DeclIterator::VisitNamespaceAliasDecl(NamespaceAliasDecl *D) {
}

void DeclIterator::VisitCXXRecordDecl(CXXRecordDecl *D) {
    VisitDeclContext(D);
}

void DeclIterator::VisitLinkageSpecDecl(LinkageSpecDecl *D) {
  if (D->hasBraces()) {
    VisitDeclContext(D);
  } else
    Visit(*D->decls_begin());
}

void DeclIterator::VisitFunctionTemplateDecl(FunctionTemplateDecl *D) {
    return;
    return;
    for (FunctionTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end();
         I != E; ++I) {
        Visit(*I);
    }

  return VisitRedeclarableTemplateDecl(D);
}

void DeclIterator::VisitClassTemplateDecl(ClassTemplateDecl *D) {
    return;
    for (ClassTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end();
         I != E; ++I) {
        Visit(*I);
    }

    VisitRedeclarableTemplateDecl(D);
}

void DeclIterator::VisitTemplateDecl(const TemplateDecl *D) {
    return;
  // if (const TemplateTemplateParmDecl *TTP =
  //     dyn_cast<TemplateTemplateParmDecl>(D)) {
  //     return;
  // } else {
  //   Visit(D->getTemplatedDecl());
  // }
}

static SourceRange getDeclRange(SourceManager *SM, const LangOptions *langOpts, const clang::Decl *D, bool with_semicolon)
{
    clang::SourceLocation SLoc = SM->getExpansionLoc(D->getLocStart());
	clang::SourceLocation ELoc = SM->getExpansionLoc(D->getLocEnd());
	unsigned start = SM->getFileOffset(SLoc);
	unsigned end   = SM->getFileOffset(ELoc);

	// Below code copied from clang::Lexer::MeasureTokenLength():
	clang::SourceLocation Loc = SM->getExpansionLoc(ELoc);
	std::pair<clang::FileID, unsigned> LocInfo = SM->getDecomposedLoc(Loc);
	llvm::StringRef Buffer = SM->getBufferData(LocInfo.first);
	const char *StrData = Buffer.data()+LocInfo.second;
	Lexer TheLexer(Loc, *langOpts, Buffer.begin(), StrData, Buffer.end());
	Token token;
	TheLexer.LexFromRawLexer(token);
	end += token.getLength();

    if (!with_semicolon) {
        return SourceRange(SourceLocation::getFromRawEncoding(start), SourceLocation::getFromRawEncoding(end + 2));
    }

	if (token.isNot(clang::tok::semi) && token.isNot(clang::tok::r_brace)) {
		TheLexer.LexFromRawLexer(token);
		if (token.is(clang::tok::semi)) {
			end += token.getLength();
		}
	}

	return SourceRange(SourceLocation::getFromRawEncoding(start), SourceLocation::getFromRawEncoding(end + 3));
}

void StmtIterator::VisitStmt(Stmt *S)
{

    for (Stmt::child_range C = S->children(); C; ++C) {
        if (*C) {
            Visit(*C);
        }
    }
}

void StmtIterator::VisitDeclStmt(DeclStmt *S)
{

    VisitStmt(S);
    for (DeclStmt::decl_iterator D = S->decl_begin(), DEnd = S->decl_end();
         D != DEnd; ++D)
        VisitDecl(*D);
}

void StmtIterator::VisitNullStmt(NullStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCompoundStmt(CompoundStmt *S)
{
    
    VisitStmt(S);
}

void StmtIterator::VisitSwitchCase(SwitchCase *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCaseStmt(CaseStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCXXForRangeStmt(CXXForRangeStmt *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitArrayTypeTraitExpr(ArrayTypeTraitExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitAsTypeExpr(AsTypeExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitAtomicExpr(AtomicExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCBridgedCastExpr(ObjCBridgedCastExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCAutoreleasePoolStmt(clang::ObjCAutoreleasePoolStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHExceptStmt(SEHExceptStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHFinallyStmt(SEHFinallyStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHTryStmt(SEHTryStmt *S) {

    VisitStmt(S);
}


void StmtIterator::VisitExpressionTraitExpr(ExpressionTraitExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitGenericSelectionExpr(GenericSelectionExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitMaterializeTemporaryExpr(MaterializeTemporaryExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCIndirectCopyRestoreExpr(ObjCIndirectCopyRestoreExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitSubstNonTypeTemplateParmExpr(SubstNonTypeTemplateParmExpr *S) {

    VisitStmt(S);
}

void StmtIterator::VisitUnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *S) {

    VisitStmt(S);
}

void StmtIterator::VisitDefaultStmt(DefaultStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitLabelStmt(LabelStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitIfStmt(IfStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitSwitchStmt(SwitchStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitWhileStmt(WhileStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitDoStmt(DoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitForStmt(ForStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitGotoStmt(GotoStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitIndirectGotoStmt(IndirectGotoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitContinueStmt(ContinueStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitBreakStmt(BreakStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitReturnStmt(ReturnStmt *S)
{

    const FunctionDecl* FD = cast<FunctionDecl>(D);

    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "std::")) {
        return;
    }
    
    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "_trace_represent")) {
        return;
    }

    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return;
        }
    }

    if (FD->hasAttr<NoInstrumentFunctionAttr>() || FD->isInlined()) {
        return;
    }

    SourceLocation startLoc = S->getLocStart();
    SourceLocation onePastSemiLoc = getReturnStmtEnd(ast, Rewrite, S);
    
    TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(FD->getQualifiedNameAsString());
    
    TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
    trace_call.setSeverity(severity);
    trace_call.addTraceParam(function_name_param);
    if (NULL == S->getRetValue()) {
        goto expand;
    }
    
    if (trace_param.fromExpr(S->getRetValue(), false) && !(S->getRetValue()->HasSideEffects(ast))) {
        trace_call.addTraceParam(trace_param);
        VisitStmt(S);
    }

expand:
   std::string traceExpansion = trace_call.getExpansion();
   Rewrite->InsertText(onePastSemiLoc, "}", true);
   Rewrite->ReplaceText(startLoc, 6, "{if (current_trace_buffer != 0) {trace_decrement_nesting_level(); " + traceExpansion + "} return ");
   return;
}

void StmtIterator::VisitAsmStmt(AsmStmt *S)
{

    VisitStmt(S);
    VisitStringLiteral(S->getAsmString());
    for (unsigned I = 0, N = S->getNumOutputs(); I != N; ++I)
    {
        VisitStringLiteral(S->getOutputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumInputs(); I != N; ++I)
    {
        VisitStringLiteral(S->getInputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumClobbers(); I != N; ++I)
        VisitStringLiteral(S->getClobber(I));
}

void StmtIterator::VisitCXXCatchStmt(CXXCatchStmt *S)
{

    VisitStmt(S);
    VisitType(S->getCaughtType());
}

void StmtIterator::VisitCXXTryStmt(CXXTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCForCollectionStmt(ObjCForCollectionStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtCatchStmt(ObjCAtCatchStmt *S)
{

    VisitStmt(S);
    if (S->getCatchParamDecl())
        VisitType(S->getCatchParamDecl()->getType());
}

void StmtIterator::VisitObjCAtFinallyStmt(ObjCAtFinallyStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtTryStmt(ObjCAtTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtSynchronizedStmt(ObjCAtSynchronizedStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtThrowStmt(ObjCAtThrowStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitExpr(Expr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitDeclRefExpr(DeclRefExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitDecl(S->getDecl());
    VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitPredefinedExpr(PredefinedExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitIntegerLiteral(IntegerLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCharacterLiteral(CharacterLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitFloatingLiteral(FloatingLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImaginaryLiteral(ImaginaryLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitStringLiteral(StringLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitParenExpr(ParenExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitParenListExpr(ParenListExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitUnaryOperator(UnaryOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitOffsetOfExpr(OffsetOfExpr *S)
{

    VisitType(S->getTypeSourceInfo()->getType());
    unsigned n = S->getNumComponents();
    for (unsigned i = 0; i < n; ++i)
    {
        const OffsetOfExpr::OffsetOfNode& ON = S->getComponent(i);
        switch (ON.getKind())
        {
        case OffsetOfExpr::OffsetOfNode::Array:
            // Expressions handled below.
            break;

        case OffsetOfExpr::OffsetOfNode::Field:
            VisitDecl(ON.getField());
            break;

        case OffsetOfExpr::OffsetOfNode::Identifier:
            break;

        case OffsetOfExpr::OffsetOfNode::Base:
            // These nodes are implicit, and therefore don't need profiling.
            break;
        }
    }

    VisitExpr(S);
}

// void StmtIterator::VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *S)
// {

//     VisitExpr(S);
//     if (S->isArgumentType())
//         VisitType(S->getArgumentType());
// }

void StmtIterator::VisitArraySubscriptExpr(ArraySubscriptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCallExpr(CallExpr *S)
{
    
    TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    bool successfully_parsed = trace_call.fromCallExpr(S);
    if (successfully_parsed) {
        if (getCallExprFunctionName(S).compare("REPR") == 0) {
            trace_call.expandWithoutDeclaration();
        } else {
            trace_call.expand();
        }
    }
    
    VisitExpr(S);
}

void StmtIterator::VisitMemberExpr(MemberExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getMemberDecl());
    VisitNestedNameSpecifier(S->getQualifier());
}

void StmtIterator::VisitCompoundLiteralExpr(CompoundLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCastExpr(CastExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImplicitCastExpr(ImplicitCastExpr *S)
{

    VisitCastExpr(S);
}

void StmtIterator::VisitExplicitCastExpr(ExplicitCastExpr *S)
{

    VisitCastExpr(S);
    VisitType(S->getTypeAsWritten());
}

void StmtIterator::VisitCStyleCastExpr(CStyleCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitBinaryOperator(BinaryOperator *S)
{

//    VisitExpr(S);
}

void StmtIterator::VisitCompoundAssignOperator(CompoundAssignOperator *S)
{

    VisitBinaryOperator(S);
}

void StmtIterator::VisitConditionalOperator(ConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitBinaryConditionalOperator(BinaryConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitAddrLabelExpr(AddrLabelExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitStmtExpr(StmtExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitShuffleVectorExpr(ShuffleVectorExpr *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitChooseExpr(ChooseExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitGNUNullExpr(GNUNullExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitVAArgExpr(VAArgExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitInitListExpr(InitListExpr *S)
{

    if (S->getSyntacticForm())
    {
        VisitInitListExpr(S->getSyntacticForm());
        return;
    }

    VisitExpr(S);
}

void StmtIterator::VisitDesignatedInitExpr(DesignatedInitExpr *S)
{

    VisitExpr(S);
    for (DesignatedInitExpr::designators_iterator D = S->designators_begin(),
             DEnd = S->designators_end();
         D != DEnd; ++D)
    {
        if (D->isFieldDesignator())
        {
            VisitName(D->getFieldName());
            continue;
        }
    }
}

void StmtIterator::VisitImplicitValueInitExpr(ImplicitValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitExtVectorElementExpr(ExtVectorElementExpr *S)
{

    VisitExpr(S);
    VisitName(&S->getAccessor());
}

void StmtIterator::VisitBlockExpr(BlockExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getBlockDecl());
}

void StmtIterator::VisitBlockDeclRefExpr(BlockDeclRefExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitCXXOperatorCallExpr(CXXOperatorCallExpr *S)
{

    if (S->isTypeDependent()) {
        for (unsigned I = 0, N = S->getNumArgs(); I != N; ++I)
            Visit(S->getArg(I));
        return;
    }

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXMemberCallExpr(CXXMemberCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCUDAKernelCallExpr(CUDAKernelCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXNamedCastExpr(CXXNamedCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXStaticCastExpr(CXXStaticCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXDynamicCastExpr(CXXDynamicCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXReinterpretCastExpr(CXXReinterpretCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXConstCastExpr(CXXConstCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXBoolLiteralExpr(CXXBoolLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXNullPtrLiteralExpr(CXXNullPtrLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXTypeidExpr(CXXTypeidExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXUuidofExpr(CXXUuidofExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXThisExpr(CXXThisExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXThrowExpr(CXXThrowExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDefaultArgExpr(CXXDefaultArgExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParam());
}

void StmtIterator::VisitCXXBindTemporaryExpr(CXXBindTemporaryExpr *S)
{

    VisitExpr(S);
    VisitDecl(
        const_cast<CXXDestructorDecl *>(S->getTemporary()->getDestructor()));
}

void StmtIterator::VisitCXXConstructExpr(CXXConstructExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getConstructor());
}

void StmtIterator::VisitCXXFunctionalCastExpr(CXXFunctionalCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXTemporaryObjectExpr(CXXTemporaryObjectExpr *S)
{

    VisitCXXConstructExpr(S);
}

void StmtIterator::VisitCXXScalarValueInitExpr(CXXScalarValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDeleteExpr(CXXDeleteExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getOperatorDelete());
}

void StmtIterator::VisitCXXNewExpr(CXXNewExpr *S)
{

    VisitExpr(S);
    VisitType(S->getAllocatedType());
    VisitDecl(S->getOperatorNew());
    VisitDecl(S->getOperatorDelete());
    VisitDecl(S->getConstructor());
}

void StmtIterator::VisitCXXPseudoDestructorExpr(CXXPseudoDestructorExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitType(S->getDestroyedType());
}

void StmtIterator::VisitOverloadExpr(OverloadExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getExplicitTemplateArgs().getTemplateArgs(),
                               S->getExplicitTemplateArgs().NumTemplateArgs);
}

void
StmtIterator::VisitUnresolvedLookupExpr(UnresolvedLookupExpr *S)
{

    VisitOverloadExpr(S);
}

void StmtIterator::VisitUnaryTypeTraitExpr(UnaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getQueriedType());
}

void StmtIterator::VisitBinaryTypeTraitExpr(BinaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getLhsType());
    VisitType(S->getRhsType());
}

void
StmtIterator::VisitDependentScopeDeclRefExpr(DependentScopeDeclRefExpr *S)
{

    VisitExpr(S);
    VisitName(S->getDeclName());
    VisitNestedNameSpecifier(S->getQualifier());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitExprWithCleanups(ExprWithCleanups *S)
{

    VisitExpr(S);
}

void
StmtIterator::VisitCXXUnresolvedConstructExpr(CXXUnresolvedConstructExpr *S)
{

    VisitExpr(S);
    VisitType(S->getTypeAsWritten());
}

void
StmtIterator::VisitCXXDependentScopeMemberExpr(CXXDependentScopeMemberExpr *S)
{

    if (!S->isImplicitAccess())
    {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMember());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitUnresolvedMemberExpr(UnresolvedMemberExpr *S)
{

    if (!S->isImplicitAccess())
    {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMemberName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitCXXNoexceptExpr(CXXNoexceptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitPackExpansionExpr(PackExpansionExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitSizeOfPackExpr(SizeOfPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getPack());
}

void StmtIterator::VisitSubstNonTypeTemplateParmPackExpr(
    SubstNonTypeTemplateParmPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParameterPack());
    VisitTemplateArgument(S->getArgumentPack());
}

void StmtIterator::VisitOpaqueValueExpr(OpaqueValueExpr *E)
{

    VisitExpr(E);
}

void StmtIterator::VisitObjCStringLiteral(ObjCStringLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitObjCEncodeExpr(ObjCEncodeExpr *S)
{

    VisitExpr(S);
    VisitType(S->getEncodedType());
}

void StmtIterator::VisitObjCSelectorExpr(ObjCSelectorExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
}

void StmtIterator::VisitObjCProtocolExpr(ObjCProtocolExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getProtocol());
}

void StmtIterator::VisitObjCIvarRefExpr(ObjCIvarRefExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *S)
{

    VisitExpr(S);
    if (S->isImplicitProperty())
    {
        VisitDecl(S->getImplicitPropertyGetter());
        VisitDecl(S->getImplicitPropertySetter());
    } else {
        VisitDecl(S->getExplicitProperty());
    }
    if (S->isSuperReceiver())
    {
        VisitType(S->getSuperReceiverType());
    }
}

void StmtIterator::VisitObjCMessageExpr(ObjCMessageExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
    VisitDecl(S->getMethodDecl());
}

void StmtIterator::VisitObjCIsaExpr(ObjCIsaExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitDecl(Decl *D)
{

}

void StmtIterator::VisitType(QualType T)
{

}

void StmtIterator::VisitName(DeclarationName Name)
{

}

void StmtIterator::VisitNestedNameSpecifier(NestedNameSpecifier *NNS)
{

}

void StmtIterator::VisitTemplateName(TemplateName Name)
{

}

void StmtIterator::VisitTemplateArguments(const TemplateArgumentLoc *Args,
                                          unsigned NumArgs)
{

    for (unsigned I = 0; I != NumArgs; ++I)
        VisitTemplateArgument(Args[I].getArgument());
}

void StmtIterator::VisitTemplateArgument(const TemplateArgument &Arg)
{
    // Mostly repetitive with TemplateArgument::Profile!
    switch (Arg.getKind())
    {
    case TemplateArgument::Null:
        break;

    case TemplateArgument::Type:
        VisitType(Arg.getAsType());
        break;

    case TemplateArgument::Template:
    case TemplateArgument::TemplateExpansion:
        VisitTemplateName(Arg.getAsTemplateOrTemplatePattern());
        break;

    case TemplateArgument::Declaration:
        VisitDecl(Arg.getAsDecl());
        break;

    case TemplateArgument::Integral:
        VisitType(Arg.getIntegralType());
        break;

    case TemplateArgument::Expression:
        Visit(Arg.getAsExpr());
        break;

    case TemplateArgument::Pack:
        const TemplateArgument *Pack = Arg.pack_begin();
        for (unsigned i = 0, e = Arg.pack_size(); i != e; ++i)
            VisitTemplateArgument(Pack[i]);
        break;
    }
}

class PreCompilationLogsConsumer : public ASTConsumer {
public:
    llvm::raw_ostream& Out;
    DiagnosticsEngine &Diags;
    raw_ostream *OutFile;
    FileID MainFileID;
    SourceManager *SM;
    std::string InFileName;
    std::stringstream type_definition;
    std::stringstream global_traces;
    CompilerInstance *compilerInstance;
    
    PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out, CompilerInstance &CI);

    
    std::string replaceOnce(
        std::string result, 
        const std::string& replaceWhat, 
        const std::string& replaceWithWhat)
        {
            const int pos = result.find(replaceWhat);
            if (pos==-1) return result;
            result.replace(pos,replaceWhat.size(),replaceWithWhat);
            return result;
        }
    
    std::string typeSectionName(std::string type_str) {
        return "." + replaceAll(type_str, " ", ".");
    } 

    std::string stringArrayDefinition(std::string str) {
        std::stringstream array_def;
        const char *s = str.c_str();
        array_def << "{";
        while (*s != '\0') {
            array_def << "'" << *s << "' ,";
            s++;
        }

        array_def << "'\\0' }";
        return array_def.str();
    }
    
    std::string getEnumMemberTraceDefinition(EnumDecl *ED, std::string &section_name, std::string &param_name) {
        std::stringstream enum_members;

        for (EnumDecl::enumerator_iterator
                 Enum = ED->enumerator_begin(), EnumEnd = ED->enumerator_end();
             Enum != EnumEnd; ++Enum) { 
            enum_members << "static char __attribute__((__section__(\".gnu.linkonce.type.enum" << section_name << ".data\"))) __attribute__((aligned(1)))" << param_name + Enum->getName().data() << "_str[] = " << stringArrayDefinition(Enum->getName().data()) << ";";
        }

        enum_members << "static struct trace_enum_value __attribute__((__section__(\".gnu.linkonce.type.enum" << section_name << ".data\"))) __attribute__((aligned(1)))" << param_name << "[] = {";
        for (EnumDecl::enumerator_iterator
                 Enum = ED->enumerator_begin(), EnumEnd = ED->enumerator_end();
             Enum != EnumEnd; ++Enum) {
            enum_members << "{" << param_name + Enum->getName().data() << "_str, " << Enum->getInitVal().getZExtValue() << "},";
        }

        enum_members << "{0, 0}}; ";
        return enum_members.str();
    }
    
    void declareEnumeralType(const EnumType *type) {
        EnumDecl *ED = type->getDecl();
        std::string type_str = normalizeTypeName(QualType(type, 0).getAsString());
        std::string section_name = typeSectionName(QualType(type, 0).getAsString());
        std::string type_param_var_name = type_str + "_type_params";
        std::string section_defs_attribute =  "__attribute__((__section__(\".gnu.linkonce.type.enum" + section_name + ".defs\"))) __attribute__((aligned(1)))";
        std::string section_ptr_attribute =  "__attribute__((__section__(\".gnu.linkonce.type.enum" + section_name + ".ptr\"))) __attribute__((aligned(1)))";

        std::string type_def_name = type_str + "_type_definition";
        type_definition << "extern struct trace_type_definition " << type_def_name << ";";
        type_definition << "struct trace_type_definition " << section_ptr_attribute << "* " << type_str << "_ptr = " << "&" << type_def_name << ";";
        type_definition << getEnumMemberTraceDefinition(ED, section_name, type_param_var_name);
        type_definition << "struct trace_type_definition " << section_defs_attribute  << type_str << "_type_definition = {";
        type_definition << "TRACE_TYPE_ID_ENUM, \"" <<  QualType(type, 0).getAsString() << "\", {" << type_param_var_name  << "}};";
        type_definition << "\n";
    }
        
    void mapType(const Type *type) {
        if (type->isEnumeralType()) {
            const EnumType *enum_type = type->getAs<EnumType>();
            declareEnumeralType(enum_type);
        }
    }

    void buildNullType() {
        type_definition << "void __attribute__((__section__(\".gnu.linkonce.null_type""\"))) __attribute__((aligned(1))) *null_type = 0; ";
    }
    
    void buildReferencedTypes() {
        std::set<const Type *>::iterator iter;
        for (iter = referencedTypes.begin(); iter != referencedTypes.end(); ++iter) {
            mapType(*iter);
        }

        buildNullType();
    }

    void buildGlobalTraces() {
        std::set<TraceCall *>::iterator iter;
        for (iter = globalTraces.begin(); iter != globalTraces.end(); ++iter) {
            global_traces << (*iter)->getTraceDeclaration();
        }
    }


    void writeGlobalTraces(ASTContext &C) {
        StructFinder struct_finder;
        RecordDecl *record_struct = struct_finder.findDeclByName(C.getTranslationUnitDecl(), "trace_log_descriptor");
        if (record_struct == NULL) {
            exit(1);
            return;
        }

        SourceRange range = getDeclRange(SM, &C.getLangOptions(), record_struct, true);
        Rewrite.InsertText(range.getEnd(), global_traces.str());
    }
    
    void HandleTranslationUnit(ASTContext &C) {
        Rewrite.setSourceMgr(C.getSourceManager(), C.getLangOptions());
        SM = &C.getSourceManager();
        MainFileID = SM->getMainFileID();
        DeclIterator decliterator(Out, Diags, C, &Rewrite, SM, C.getLangOptions(), referencedTypes, globalTraces);
        decliterator.Visit(C.getTranslationUnitDecl());
        buildReferencedTypes();
        buildGlobalTraces();
        if (const RewriteBuffer *RewriteBuf =
            Rewrite.getRewriteBufferFor(MainFileID)) {
            *OutFile << std::string(RewriteBuf->begin(), RewriteBuf->end());
            *OutFile << type_definition.str();
        } else {
            StringRef buffer = SM->getBufferData(MainFileID).data();
            *OutFile << std::string(buffer);
        }
    }

private:
    std::set<const Type *> referencedTypes;
    std::set<TraceCall *> globalTraces;
    Rewriter Rewrite;
};

PreCompilationLogsConsumer::PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out, CompilerInstance &CI)
    : Out(llvm::errs()), Diags(CI.getDiagnostics()), OutFile(out), InFileName(inFile), compilerInstance(&CI)
{
}

class InstrumentCodeAction : public PluginASTAction {
private:
    raw_ostream *OS;
    StringRef InFile;
    CompilerInstance *CI;
protected:
    ASTConsumer *CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile) {
        if (raw_ostream *OS = CI.createDefaultOutputFile(false, InFile, "cpp"))
            return new PreCompilationLogsConsumer(InFile, OS, CI);
        else {
            return NULL;
        }
    }

    bool ParseArgs(const CompilerInstance &CI,
                   const std::vector<std::string>& args) {
        return true;
    }
    
    void PrintHelp(llvm::raw_ostream& ros) {
        ros << "\n";
    }

};

}

static FrontendPluginRegistry::Add<InstrumentCodeAction>
X("trace-instrument", "Instrument code for traces");
