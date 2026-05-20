/* FunctionAdvancedEndpoints — Tier 10: deep function manipulation.
 *
 *   /functions/create              — create a function at addr
 *   /functions/delete              — remove function
 *   /functions/set_return_type     — set return type
 *   /functions/list_parameters     — current params
 *   /functions/set_parameter       — set type/name of param[i]
 *   /functions/list_locals         — current locals
 *   /functions/set_local           — set local var type/name
 *   /functions/add_tag             — add a function tag
 *   /functions/remove_tag          — remove tag
 *   /functions/list_calling_conv   — calling conventions known to program
 *   /functions/set_calling_conv    — apply CC to function
 *   /functions/set_attrs           — flip no_return / inline / varargs
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class FunctionAdvancedEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public FunctionAdvancedEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    private static DataType findType(DataTypeManager dtm, String name) {
        if (name == null) return null;
        DataType d = dtm.getDataType(name);
        if (d != null) return d;
        ArrayList<DataType> hits = new ArrayList<>();
        dtm.findDataTypes(name, hits);
        return hits.isEmpty() ? null : hits.get(0);
    }

    // ── /functions/create ────────────────────────────────────────────

    public void handleCreate(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String name = q.getOrDefault("name", "FUN_" + (a != null ? a.toString() : "unknown"));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/create");
        boolean ok = false;
        String error = null;
        Function fn = null;
        try {
            fn = prog.getFunctionManager().createFunction(name, a, new AddressSet(a, a),
                    SourceType.USER_DEFINED);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok || fn == null) { Http.error(ex, 500, error == null ? "create failed" : error); return; }
        Http.ok(ex, Map.of("name", fn.getName(), "addr", fn.getEntryPoint().toString()));
    }

    // ── /functions/delete ────────────────────────────────────────────

    public void handleDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        FunctionManager fm = prog.getFunctionManager();
        int tx = prog.startTransaction("decepticon mcp: functions/delete");
        boolean removed = false;
        try {
            removed = fm.removeFunction(a);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("addr", a.toString(), "removed", removed));
    }

    // ── /functions/set_return_type ───────────────────────────────────

    public void handleSetReturnType(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String type = q.get("type");
        if (a == null || type == null) { Http.error(ex, 400, "need 'addr' + 'type'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        DataType dt = findType(prog.getDataTypeManager(), type);
        if (dt == null) { Http.error(ex, 404, "no type " + type); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/set_return_type");
        boolean ok = false;
        String error = null;
        try {
            fn.setReturnType(dt, SourceType.USER_DEFINED);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("function", fn.getName(), "return_type", dt.getName()));
    }

    // ── /functions/list_parameters ───────────────────────────────────

    public void handleListParameters(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Parameter p : fn.getParameters()) {
            out.add(Map.of(
                "ordinal", p.getOrdinal(),
                "name", p.getName(),
                "type", p.getDataType().getName(),
                "length", p.getLength()
            ));
        }
        Http.ok(ex, Map.of("function", fn.getName(), "count", out.size(), "parameters", out));
    }

    // ── /functions/set_parameter ─────────────────────────────────────

    public void handleSetParameter(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        Integer idx = parseIntegerOrNull(q.get("ordinal"));
        String name = q.get("name");
        String type = q.get("type");
        if (a == null || idx == null) { Http.error(ex, 400, "need 'addr' + 'ordinal'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        Parameter[] ps = fn.getParameters();
        if (idx < 0 || idx >= ps.length) { Http.error(ex, 404, "ordinal out of range"); return; }
        Parameter p = ps[idx];
        int tx = prog.startTransaction("decepticon mcp: functions/set_parameter");
        boolean ok = false;
        String error = null;
        try {
            if (name != null) p.setName(name, SourceType.USER_DEFINED);
            if (type != null) {
                DataType dt = findType(prog.getDataTypeManager(), type);
                if (dt != null) p.setDataType(dt, SourceType.USER_DEFINED);
            }
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "ordinal", idx,
            "name", p.getName(),
            "type", p.getDataType().getName()
        ));
    }

    // ── /functions/list_locals ───────────────────────────────────────

    public void handleListLocals(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Variable v : fn.getLocalVariables()) {
            out.add(Map.of(
                "name", v.getName(),
                "type", v.getDataType().getName(),
                "length", v.getLength(),
                "stack_offset", v.isStackVariable() ? v.getStackOffset() : Integer.MIN_VALUE,
                "kind", v.isStackVariable() ? "stack" : (v.isRegisterVariable() ? "register" : "other")
            ));
        }
        Http.ok(ex, Map.of("function", fn.getName(), "count", out.size(), "locals", out));
    }

    // ── /functions/set_local ─────────────────────────────────────────

    public void handleSetLocal(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String oldName = q.get("old_name");
        String name = q.get("name");
        String type = q.get("type");
        if (a == null || oldName == null) { Http.error(ex, 400, "need 'addr' + 'old_name'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        Variable target = null;
        for (Variable v : fn.getLocalVariables()) {
            if (oldName.equals(v.getName())) { target = v; break; }
        }
        if (target == null) { Http.error(ex, 404, "no local " + oldName); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/set_local");
        boolean ok = false;
        String error = null;
        try {
            if (name != null) target.setName(name, SourceType.USER_DEFINED);
            if (type != null) {
                DataType dt = findType(prog.getDataTypeManager(), type);
                if (dt != null) target.setDataType(dt, SourceType.USER_DEFINED);
            }
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of(
            "function", fn.getName(),
            "old_name", oldName,
            "name", target.getName(),
            "type", target.getDataType().getName()
        ));
    }

    // ── /functions/add_tag + /functions/remove_tag ───────────────────

    public void handleAddTag(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String tag = q.get("tag");
        if (a == null || tag == null) { Http.error(ex, 400, "need 'addr' + 'tag'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/add_tag");
        boolean ok = false;
        try { ok = fn.addTag(tag); }
        finally { prog.endTransaction(tx, true); }
        Http.ok(ex, Map.of("function", fn.getName(), "tag", tag, "added", ok));
    }

    public void handleRemoveTag(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String tag = q.get("tag");
        if (a == null || tag == null) { Http.error(ex, 400, "need 'addr' + 'tag'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/remove_tag");
        try { fn.removeTag(tag); }
        finally { prog.endTransaction(tx, true); }
        Http.ok(ex, Map.of("function", fn.getName(), "tag", tag, "removed", true));
    }

    // ── /functions/list_calling_conv ─────────────────────────────────

    public void handleListCallingConv(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        FunctionManager fm = prog.getFunctionManager();
        String[] ccs = fm.getCallingConventionNames().toArray(new String[0]);
        String def = fm.getDefaultCallingConvention() != null
                     ? fm.getDefaultCallingConvention().getName() : "(none)";
        Http.ok(ex, Map.of("default", def, "calling_conventions", ccs));
    }

    // ── /functions/set_calling_conv ──────────────────────────────────

    public void handleSetCallingConv(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        String cc = q.get("calling_convention");
        if (a == null || cc == null) { Http.error(ex, 400, "need 'addr' + 'calling_convention'"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/set_calling_conv");
        boolean ok = false;
        String error = null;
        try {
            fn.setCallingConvention(cc);
            ok = true;
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        } finally {
            prog.endTransaction(tx, ok);
        }
        if (!ok) { Http.error(ex, 500, error); return; }
        Http.ok(ex, Map.of("function", fn.getName(), "calling_convention", cc));
    }

    // ── /functions/set_attrs ─────────────────────────────────────────

    public void handleSetAttrs(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        Address a = prog.getAddressFactory().getAddress(q.getOrDefault("addr", ""));
        if (a == null) { Http.error(ex, 400, "bad addr"); return; }
        Function fn = prog.getFunctionManager().getFunctionContaining(a);
        if (fn == null) { Http.error(ex, 404, "no function at addr"); return; }
        int tx = prog.startTransaction("decepticon mcp: functions/set_attrs");
        Map<String, Object> applied = new HashMap<>();
        try {
            if (q.containsKey("no_return")) {
                boolean v = "true".equalsIgnoreCase(q.get("no_return"));
                fn.setNoReturn(v); applied.put("no_return", v);
            }
            if (q.containsKey("inline")) {
                boolean v = "true".equalsIgnoreCase(q.get("inline"));
                fn.setInline(v); applied.put("inline", v);
            }
            if (q.containsKey("varargs")) {
                boolean v = "true".equalsIgnoreCase(q.get("varargs"));
                fn.setVarArgs(v); applied.put("varargs", v);
            }
            if (q.containsKey("custom_storage")) {
                boolean v = "true".equalsIgnoreCase(q.get("custom_storage"));
                fn.setCustomVariableStorage(v); applied.put("custom_storage", v);
            }
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("function", fn.getName(), "applied", applied));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static Integer parseIntegerOrNull(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }
}
