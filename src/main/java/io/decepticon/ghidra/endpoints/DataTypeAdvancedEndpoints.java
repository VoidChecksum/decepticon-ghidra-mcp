/* DataTypeAdvancedEndpoints — Tier 9: data type creation + CRUD.
 *
 *   /types/create_struct       — new empty struct
 *   /types/add_struct_field    — append/replace component
 *   /types/create_union        — new empty union
 *   /types/create_enum         — new enum w/ initial entries
 *   /types/add_enum_entry      — add name=value to enum
 *   /types/create_typedef      — alias for existing type
 *   /types/create_pointer      — pointer to base type
 *   /types/create_array        — array[N] of base type
 *   /types/list_categories     — all categories in the type manager
 *   /types/create_category     — new category path
 *   /types/find_by_name        — search types by name fragment
 *   /types/delete              — remove type
 */

package io.decepticon.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Program;

import io.decepticon.ghidra.util.Http;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class DataTypeAdvancedEndpoints {

    private final PcodeEndpoints.ProgramAccessor pa;

    public DataTypeAdvancedEndpoints(PcodeEndpoints.ProgramAccessor pa) { this.pa = pa; }

    private static DataType findType(DataTypeManager dtm, String name) {
        DataType d = dtm.getDataType(name);
        if (d != null) return d;
        ArrayList<DataType> hits = new ArrayList<>();
        dtm.findDataTypes(name, hits);
        return hits.isEmpty() ? null : hits.get(0);
    }

    // ── /types/create_struct ─────────────────────────────────────────

    public void handleCreateStruct(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        int size = parseIntOr(q.get("size"), 0);
        DataTypeManager dtm = prog.getDataTypeManager();
        int tx = prog.startTransaction("decepticon mcp: types/create_struct");
        try {
            StructureDataType s = new StructureDataType(name, size, dtm);
            DataType added = dtm.addDataType(s, null);
            Http.ok(ex, Map.of(
                "name", added.getName(),
                "path", added.getPathName(),
                "length", added.getLength()
            ));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/add_struct_field ──────────────────────────────────────

    public void handleAddStructField(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String structName = q.get("struct");
        String fieldName = q.get("field_name");
        String fieldType = q.get("field_type");
        Integer offset = parseIntegerOrNull(q.get("offset"));  // null = append
        if (structName == null || fieldName == null || fieldType == null) {
            Http.error(ex, 400, "need 'struct' + 'field_name' + 'field_type'"); return;
        }
        DataTypeManager dtm = prog.getDataTypeManager();
        DataType t = findType(dtm, structName);
        if (!(t instanceof Structure s)) { Http.error(ex, 404, "no struct " + structName); return; }
        DataType ft = findType(dtm, fieldType);
        if (ft == null) { Http.error(ex, 404, "no type " + fieldType); return; }
        int tx = prog.startTransaction("decepticon mcp: types/add_struct_field");
        try {
            if (offset == null) {
                s.add(ft, fieldName, null);
            } else {
                s.insertAtOffset(offset, ft, ft.getLength(), fieldName, null);
            }
            Http.ok(ex, Map.of(
                "struct", structName,
                "field_name", fieldName,
                "field_type", ft.getName(),
                "offset", offset == null ? s.getLength() - ft.getLength() : offset,
                "new_size", s.getLength()
            ));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/create_union ──────────────────────────────────────────

    public void handleCreateUnion(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        DataTypeManager dtm = prog.getDataTypeManager();
        int tx = prog.startTransaction("decepticon mcp: types/create_union");
        try {
            UnionDataType u = new UnionDataType(name);
            DataType added = dtm.addDataType(u, null);
            Http.ok(ex, Map.of("name", added.getName(), "path", added.getPathName()));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/create_enum ───────────────────────────────────────────

    public void handleCreateEnum(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        int size = parseIntOr(q.get("size"), 4);
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        DataTypeManager dtm = prog.getDataTypeManager();
        int tx = prog.startTransaction("decepticon mcp: types/create_enum");
        try {
            EnumDataType e = new EnumDataType(name, size);
            DataType added = dtm.addDataType(e, null);
            Http.ok(ex, Map.of("name", added.getName(), "size", size));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/add_enum_entry ────────────────────────────────────────

    public void handleAddEnumEntry(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String enumName = q.get("enum");
        String entry = q.get("entry_name");
        Long val = parseLongOrNull(q.get("value"));
        if (enumName == null || entry == null || val == null) {
            Http.error(ex, 400, "need 'enum' + 'entry_name' + 'value'"); return;
        }
        DataTypeManager dtm = prog.getDataTypeManager();
        DataType t = findType(dtm, enumName);
        // Cast to the Enum INTERFACE — DataTypeManager hands back EnumDB
        // (persistent storage subclass) not EnumDataType, but both implement
        // ghidra.program.model.data.Enum.
        if (!(t instanceof Enum e)) { Http.error(ex, 404, "no enum " + enumName); return; }
        int tx = prog.startTransaction("decepticon mcp: types/add_enum_entry");
        try {
            e.add(entry, val);
            Http.ok(ex, Map.of(
                "enum", enumName,
                "entry_name", entry,
                "value", val,
                "entry_count", e.getCount()
            ));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/create_typedef ────────────────────────────────────────

    public void handleCreateTypedef(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        String base = q.get("base");
        if (name == null || base == null) { Http.error(ex, 400, "need 'name' + 'base'"); return; }
        DataTypeManager dtm = prog.getDataTypeManager();
        DataType bd = findType(dtm, base);
        if (bd == null) { Http.error(ex, 404, "no base type " + base); return; }
        int tx = prog.startTransaction("decepticon mcp: types/create_typedef");
        try {
            TypedefDataType td = new TypedefDataType(name, bd);
            DataType added = dtm.addDataType(td, null);
            Http.ok(ex, Map.of("name", added.getName(), "base", bd.getName()));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/create_pointer ────────────────────────────────────────

    public void handleCreatePointer(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String base = q.get("base");
        if (base == null) { Http.error(ex, 400, "missing 'base'"); return; }
        DataTypeManager dtm = prog.getDataTypeManager();
        DataType bd = findType(dtm, base);
        if (bd == null) { Http.error(ex, 404, "no base type " + base); return; }
        PointerDataType p = new PointerDataType(bd, dtm);
        int tx = prog.startTransaction("decepticon mcp: types/create_pointer");
        try {
            DataType added = dtm.addDataType(p, null);
            Http.ok(ex, Map.of("name", added.getName(), "base", bd.getName(), "length", added.getLength()));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/create_array ──────────────────────────────────────────

    public void handleCreateArray(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String base = q.get("base");
        int n = parseIntOr(q.get("length"), 0);
        if (base == null || n <= 0) { Http.error(ex, 400, "need 'base' + 'length' > 0"); return; }
        DataTypeManager dtm = prog.getDataTypeManager();
        DataType bd = findType(dtm, base);
        if (bd == null) { Http.error(ex, 404, "no base " + base); return; }
        ArrayDataType arr = new ArrayDataType(bd, n, bd.getLength());
        int tx = prog.startTransaction("decepticon mcp: types/create_array");
        try {
            DataType added = dtm.addDataType(arr, null);
            Http.ok(ex, Map.of("name", added.getName(), "base", bd.getName(),
                "elements", n, "total_size", added.getLength()));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/list_categories ───────────────────────────────────────

    public void handleListCategories(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        int limit = parseIntOr(q.get("limit"), 500);
        DataTypeManager dtm = prog.getDataTypeManager();
        Category root = dtm.getRootCategory();
        List<Map<String, Object>> out = new ArrayList<>();
        walkCategory(root, out, limit);
        Http.ok(ex, Map.of("count", out.size(), "categories", out));
    }

    private static void walkCategory(Category c, List<Map<String, Object>> out, int limit) {
        if (out.size() >= limit) return;
        out.add(Map.of(
            "path", c.getCategoryPath().getPath(),
            "name", c.getName(),
            "data_type_count", c.getDataTypes().length,
            "sub_categories", c.getCategories().length
        ));
        for (Category sub : c.getCategories()) walkCategory(sub, out, limit);
    }

    // ── /types/create_category ───────────────────────────────────────

    public void handleCreateCategory(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String path = q.get("path");
        if (path == null) { Http.error(ex, 400, "missing 'path'"); return; }
        int tx = prog.startTransaction("decepticon mcp: types/create_category");
        try {
            CategoryPath cp = new CategoryPath(path);
            Category c = prog.getDataTypeManager().createCategory(cp);
            Http.ok(ex, Map.of("path", c.getCategoryPath().getPath(), "name", c.getName()));
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    // ── /types/find_by_name ──────────────────────────────────────────

    public void handleFindByName(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        ArrayList<DataType> hits = new ArrayList<>();
        prog.getDataTypeManager().findDataTypes(name, hits);
        List<Map<String, Object>> out = new ArrayList<>();
        for (DataType dt : hits) {
            out.add(Map.of(
                "name", dt.getName(),
                "path", dt.getPathName(),
                "length", dt.getLength(),
                "kind", dt.getClass().getSimpleName()
            ));
        }
        Http.ok(ex, Map.of("query", name, "count", out.size(), "types", out));
    }

    // ── /types/delete ────────────────────────────────────────────────

    public void handleDelete(HttpExchange ex) throws IOException {
        Program prog = pa.currentProgram();
        if (prog == null) { Http.error(ex, 503, "no program loaded"); return; }
        Map<String, String> q = Http.parseQuery(ex.getRequestURI().getQuery());
        String name = q.get("name");
        if (name == null) { Http.error(ex, 400, "missing 'name'"); return; }
        DataType t = findType(prog.getDataTypeManager(), name);
        if (t == null) { Http.error(ex, 404, "no type " + name); return; }
        int tx = prog.startTransaction("decepticon mcp: types/delete");
        boolean removed = false;
        try {
            removed = prog.getDataTypeManager().remove(t, ghidra.util.task.TaskMonitor.DUMMY);
        } finally {
            prog.endTransaction(tx, true);
        }
        Http.ok(ex, Map.of("name", name, "removed", removed));
    }

    // ── helpers ──────────────────────────────────────────────────────

    private static int parseIntOr(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    private static Integer parseIntegerOrNull(String s) {
        if (s == null) return null;
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }

    private static Long parseLongOrNull(String s) {
        if (s == null) return null;
        try {
            if (s.startsWith("0x")) return Long.parseUnsignedLong(s.substring(2), 16);
            return Long.parseLong(s);
        } catch (Exception e) { return null; }
    }

    @SuppressWarnings("unused")
    private static Iterator<?> unusedIter() { return null; }
}
