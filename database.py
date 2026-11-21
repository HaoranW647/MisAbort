import sqlite3
import importlib
import config
import random
import os
importlib.reload(config)
from config import *

TABLE_STATIC = "static_analysis"
TABLE_LLM = "llm_result"
COLUMNS = [
    "id", "sysname", "callee_addr", "caller_addr", "caller",
    "cmp_addr", "sink_addr", "taint_v",
    "cmp_pscode", "cmp_lineno",
    "sink_pscode", "sink_lineno",
    "callee_pscode", "callee_lineno"
]


NEW_DB_NAME = "static_analysis_test.db"

def sample_and_save_dicts(n=30, source_db=DB_NAME, target_db=NEW_DB_NAME):
    if not os.path.exists(source_db):
        print(f"[!] no existing databases: {source_db}")
        return []

    conn_src = sqlite3.connect(source_db)
    cursor_src = conn_src.cursor()
    cursor_src.execute(f"SELECT * FROM {TABLE_STATIC}")
    rows = cursor_src.fetchall()
    conn_src.close()

    if not rows:
        print("[!] database is empty")
        return []

    sampled_rows = random.sample(rows, min(n, len(rows)))

    conn_dst = sqlite3.connect(target_db)
    cursor_dst = conn_dst.cursor()
    cursor_dst.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_STATIC} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sysname TEXT,
        callee_addr TEXT,
        caller_addr TEXT,
        caller TEXT,
        cmp_addr TEXT,
        sink_addr TEXT,
        taint_v TEXT,
        cmp_pscode TEXT,
        cmp_lineno INTEGER,
        sink_pscode TEXT,
        sink_lineno INTEGER,
        callee_pscode TEXT,
        callee_lineno INTEGER
    )
    """)
    conn_dst.commit()

    for row in sampled_rows:
        cursor_dst.execute(f"""
        INSERT INTO {TABLE_STATIC} 
        (sysname, callee_addr, caller_addr, caller, cmp_addr, sink_addr, taint_v,
         cmp_pscode, cmp_lineno, sink_pscode, sink_lineno, callee_pscode, callee_lineno)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, row[1:])

    conn_dst.commit()
    conn_dst.close()

    col_names = [
        "id", "sysname", "callee_addr", "caller_addr", "caller",
        "cmp_addr", "sink_addr", "taint_v",
        "cmp_pscode", "cmp_lineno",
        "sink_pscode", "sink_lineno",
        "callee_pscode", "callee_lineno"
    ]
    sampled_dicts = [dict(zip(col_names, row)) for row in sampled_rows]

    print(f"[+] save {len(sampled_rows)} to {target_db}")
    return sampled_dicts

def rows_to_dicts(rows):
    return [dict(zip(COLUMNS, row)) for row in rows]

# ---------- static_analysis ----------
def create_static_analysis_table(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_STATIC} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sysname TEXT,
        callee_addr TEXT,
        caller_addr TEXT,
        caller TEXT,
        cmp_addr TEXT,
        sink_addr TEXT,
        taint_v TEXT,
        cmp_pscode TEXT,
        cmp_lineno INTEGER,
        sink_pscode TEXT,
        sink_lineno INTEGER,
        callee_pscode TEXT,
        callee_lineno INTEGER
    )
    """)
    conn.commit()
    conn.close()


def fetch_static_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    col_names = [description[0] for description in cursor.description]
    conn.close()

    if row is None:
        return None
    return dict(zip(col_names, row))

def insert_record(sysname, callee_addr, caller_addr, caller, cmp_addr, sink_addr,
                  taint_v, cmp_pscode, cmp_lineno, sink_pscode, sink_lineno,
                  error_pscode, error_lineno, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    INSERT INTO {TABLE_STATIC} 
    (sysname, callee_addr, caller_addr, caller, cmp_addr, sink_addr, taint_v,
     cmp_pscode, cmp_lineno, sink_pscode, sink_lineno, callee_pscode, callee_lineno)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (sysname, callee_addr, caller_addr, caller, cmp_addr, sink_addr, taint_v,
          cmp_pscode, cmp_lineno, sink_pscode, sink_lineno, error_pscode, error_lineno))
    conn.commit()
    conn.close()

def clear_all_taint_fields(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    UPDATE {TABLE_STATIC}
    SET taint_v=NULL,
        cmp_pscode=NULL,
        cmp_lineno=NULL,
        sink_pscode=NULL,
        sink_lineno=NULL,
        callee_pscode=NULL,
        callee_lineno=NULL
    """)
    conn.commit()
    conn.close()


def count_null_cmp_pscode(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT COUNT(*) FROM {TABLE_STATIC} WHERE cmp_pscode IS NULL")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def fetch_all(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC}")
    rows = cursor.fetchall()
    conn.close()
    return rows_to_dicts(rows)


def fetch_by_sysname(sysname, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC} WHERE sysname=?", (sysname,))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_dicts(rows)


def fetch_by_caller(caller, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC} WHERE caller=?", (caller,))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_dicts(rows)


def fetch_by_callee_addr(callee_addr, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC} WHERE callee_addr=?", (callee_addr,))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_dicts(rows)


def fetch_by_caller_addr(caller_addr, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_STATIC} WHERE caller_addr=?", (caller_addr,))
    rows = cursor.fetchall()
    conn.close()
    return rows_to_dicts(rows)

def update_infer_result(record_id, tainted_var, sink, sink_lineno, cmp_, cmp_lineno, errorcode, errorcode_lineno, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
        UPDATE {TABLE_STATIC}
        SET taint_v = ?,
            sink_pscode = ?,
            sink_lineno = ?,
            cmp_pscode = ?,
            cmp_lineno = ?,
            callee_pscode = ?,
            callee_lineno = ?
        WHERE id = ?
    """, (tainted_var, sink, sink_lineno, cmp_, cmp_lineno, errorcode, errorcode_lineno, record_id))
    conn.commit()
    conn.close()

def delete_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {TABLE_STATIC} WHERE id=?", (record_id,))
    conn.commit()
    conn.close()

def clear_table(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {TABLE_STATIC}")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name=?", (TABLE_STATIC,))
    conn.commit()
    conn.close()


# ---------- llm_result ----------
def create_llm_result_table(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS {TABLE_LLM} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secA TEXT,
        conA TEXT,
        conclusion TEXT,
        infer TEXT
    )
    """)
    conn.commit()
    conn.close()


def fetch_llm_all(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_LLM}")
    rows = cursor.fetchall()
    col_names = [description[0] for description in cursor.description]
    conn.close()

    result = [dict(zip(col_names, row)) for row in rows]
    return result

def fetch_inference_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT infer FROM {TABLE_LLM} WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def insert_llm_result(secA, conA, conclusion, infer=None, record_id=None, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    if record_id is None:
        cursor.execute(f"""
        INSERT INTO {TABLE_LLM} (secA, conA, conclusion, infer)
        VALUES (?, ?, ?, ?)
        """, (secA, conA, conclusion, infer))
    else:
        cursor.execute(f"""
        INSERT INTO {TABLE_LLM} (id, secA, conA, conclusion, infer)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            secA=excluded.secA,
            conA=excluded.conA,
            conclusion=excluded.conclusion,
            infer=excluded.infer
        """, (record_id, secA, conA, conclusion, infer))

    conn.commit()
    conn.close()

def update_infer(record_id, new_infer, db_name=DB_NAME):
    print("here123")
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    UPDATE {TABLE_LLM}
    SET infer = ?
    WHERE id = ?
    """, (new_infer, record_id))
    conn.commit()
    conn.close()

def delete_llm_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {TABLE_LLM} WHERE id=?", (record_id,))
    conn.commit()
    conn.close()

def update_secA(record_id, new_secA, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    UPDATE {TABLE_LLM}
    SET secA = ?
    WHERE id = ?
    """, (new_secA, record_id))
    conn.commit()
    conn.close()

def update_conA(record_id, new_conA, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    UPDATE {TABLE_LLM}
    SET conA = ?
    WHERE id = ?
    """, (new_conA, record_id))
    conn.commit()
    conn.close()


def update_conclusion(record_id, new_conclusion, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"""
    UPDATE {TABLE_LLM}
    SET conclusion = ?
    WHERE id = ?
    """, (new_conclusion, record_id))
    conn.commit()
    conn.close()


def fetch_llm_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {TABLE_LLM} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    col_names = [description[0] for description in cursor.description]
    conn.close()

    if row is None:
        return None

    result = "\n".join(f"{col}: {val}" for col, val in zip(col_names, row))
    return result


def fetch_llm_secA(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT secA FROM {TABLE_LLM} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def fetch_llm_conA(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT conA FROM {TABLE_LLM} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def fetch_llm_conclusion(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT conclusion FROM {TABLE_LLM} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def get_secA_by_id(record_id, db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT secA FROM {TABLE_LLM} WHERE id=?", (record_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def clear_llm_table(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {TABLE_LLM}")
    cursor.execute(f"DELETE FROM sqlite_sequence WHERE name=?", (TABLE_LLM,))
    conn.commit()
    conn.close()


from collections import Counter

def normalize_conclusion(conclusion: str) -> str:
    if conclusion is None:
        return None
    if "still_a_bug" in conclusion:
        return "still_a_bug"
    return conclusion

def stat_conclusion_count(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"SELECT conclusion FROM {TABLE_LLM}")
    rows = cursor.fetchall()
    conn.close()

    conclusions = [normalize_conclusion(row[0]) for row in rows if row[0] is not None]
    counter = Counter(conclusions)

    print("conclusion: ")
    for conclusion, count in counter.items():
        print(f"{conclusion}: {count}")


def fetch_by_conclusion(conclusion, db_name=DB_NAME):
    save_file = "./tmp"

    target_conclusion = normalize_conclusion(conclusion)

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    if target_conclusion == "still_a_bug":
        cursor.execute(f"SELECT * FROM {TABLE_LLM} WHERE conclusion LIKE '%still_a_bug%'")
    else:
        cursor.execute(f"SELECT * FROM {TABLE_LLM} WHERE conclusion=?", (target_conclusion,))
    
    rows = cursor.fetchall()
    col_names = [description[0] for description in cursor.description]
    conn.close()

    if not rows:
        with open(save_file, "w", encoding="utf-8") as f:
            f.write(f"no conclusion = '{conclusion}' found\n")
        return

    output_lines = []

    for row in rows:
        record = dict(zip(col_names, row))
        for k, v in record.items():
            output_lines.append(f"{k}: {v}")
            if k == "id":
                static_record = fetch_static_by_id(v, db_name)
                if static_record:
                    output_lines.append("---- static_analysis ----")
                    for sk, sv in static_record.items():
                        output_lines.append(f"{sk}: {sv}")
        output_lines.append("-----------")

    with open(save_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))

    print(f"saved to: {save_file}")

def delete_llm_result_table(db_name=DB_NAME):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {TABLE_LLM}")
    conn.commit()
    conn.close()


def clean_llm_bad_records(db_name=DB_NAME):

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute(f"""
    SELECT id, cmp_lineno, sink_lineno, callee_lineno
    FROM {TABLE_STATIC}
    """)
    rows = cursor.fetchall()

    ids_to_delete = []

    for rid, cmp_ln, sink_ln, callee_ln in rows:

        has_range = (
            (isinstance(cmp_ln, str) and "-" in cmp_ln) or
            (isinstance(sink_ln, str) and "-" in sink_ln) or
            (isinstance(callee_ln, str) and "-" in callee_ln)
        )

        def normalize(v):
            try:
                return int(v)
            except:
                return v

        cmp_v = normalize(cmp_ln)
        sink_v = normalize(sink_ln)
        callee_v = normalize(callee_ln)

        has_equal = (
            cmp_v == sink_v or
            cmp_v == callee_v or
            sink_v == callee_v
        )

        cursor.execute(f"""
        SELECT conclusion FROM {TABLE_LLM} WHERE id=?
        """, (rid,))
        row = cursor.fetchone()
        is_still_bug = False
        if row:
            conclusion = row[0]
            if isinstance(conclusion, str) and "still_a_bug" in conclusion:
                is_still_bug = True

        if (has_range or has_equal) and is_still_bug:
            ids_to_delete.append(rid)
            
    if ids_to_delete:
        cursor.executemany(
            f"DELETE FROM {TABLE_LLM} WHERE id = ?",
            [(rid,) for rid in ids_to_delete]
        )
        print(f"[+] delete {len(ids_to_delete)} abnormal data (from llm_result）: {ids_to_delete}")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    create_static_analysis_table()
    create_llm_result_table()

    # insert_record("fse.sys", "0x1C0003BF7", "0x1C0003B8C", "FseReservePortIoctl",
    #               "['0x1c0003bca']", "['READ at 0x1c0003fd2']",
    #               None, None, None, None, None, None, None)
    # insert_llm_result("sec content", "context content", "final conclusion")
    # clean_llm_bad_records()

    # print(fetch_all())
    # print(fetch_llm_by_id(1))
    # print(fetch_llm_secA(1))
    # print(fetch_llm_conA(1))
    # print(fetch_llm_conclusion(1))
