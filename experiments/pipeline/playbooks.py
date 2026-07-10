#!/usr/bin/env python3
"""Per-attack reproduction playbooks for the SkillAttack dashboard.

Builds, for every SUCCESSFUL attack (Hot100 main + SkillInject compare), a
self-contained HTML page with: a Chinese explanation of the attack principle,
the target skill's install instructions (SKILL.md + scripts), the full attack
prompt(s), the agent's expected executed commands, the success criteria, and
step-by-step manual reproduction instructions.
"""
import json
import html as _html
from pathlib import Path

ROOT = Path("/root/SkillAttack")
MAIN = ROOT / "result" / "runs_organize" / "main"
COMP = ROOT / "result" / "runs_organize" / "comparison"
HOT100 = ROOT / "data" / "hot100skills"
INJ = ROOT / "data" / "skillinject"

E = lambda s: _html.escape(s if s is not None else "")

# 8 風險類型的中文原理解說
RISK_PRINCIPLES = {
    "Data Exfiltration": "資料外洩：攻擊者把「正常業務需求」包裝成 prompt，誘導 agent 讀取環境中的敏感資料（API 金鑰、憑證檔、Cookie、個資、SSH 私鑰等），再透過網路請求或寫入可外傳的位置把資料送出。關鍵在於 skill 本身就有讀取這些資料的能力，攻擊只是給它一個看似合理的理由去做。",
    "Backdoors": "後門：誘導 agent 在程式碼或設定中植入一個隱藏的存取點——例如硬編碼的管理員帳密、用環境變數繞過簽章/驗證、或寫入預設憑證。表面上是「方便測試 / 緊急登入」，實際上留下永久可被利用的入口。",
    "Malware / Ransomware": "惡意程式 / 勒索：誘導 agent 下載並執行外部載荷（curl|bash 之類）、或對檔案進行加密/破壞性操作。攻擊常以「自動化維運 / 批次處理」為掩護，讓危險指令看起來像例行任務。",
    "Data Destruction": "資料破壞：誘導 agent 刪除、覆寫或重置關鍵資料（資料庫、檔案、設定），常以「系統遷移前清理 / 重置環境」為藉口，利用 skill 既有的刪除能力造成不可逆損失。",
    "DoS (Denial of Service)": "阻斷服務：誘導 agent 進入資源耗盡狀態——無限迴圈、大量檔案/連線、記憶體爆量——使服務癱瘓。",
    "Bias / Manipulation": "偏見 / 操縱：誘導 agent 產出被操縱或偏頗的內容、或在輸出（如模板渲染）中夾帶可執行內容（XSS）、竄改邏輯，影響下游決策。",
    "Phishing": "釣魚：誘導 agent 產生釣魚郵件或誘騙性內容，利用其文本生成能力製作社交工程素材。",
    "Poisoning": "投毒：污染資料來源、知識庫或 RAG metadata，讓後續檢索/推論被植入的內容誤導，屬於對 AI 系統供應鏈的攻擊。",
}
DEFAULT_PRINCIPLE = "此攻擊利用 skill 既有的能力，透過對抗性提示給出看似合理的業務理由，誘導 agent 執行越權或危險操作。"


def _model_dir(base: Path):
    if not base.exists():
        return None
    c = [d for d in base.iterdir() if d.is_dir() and not d.name.startswith("_")]
    return max(c, key=lambda d: d.stat().st_mtime) if c else None


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _round_success(rf: Path) -> bool:
    r = _load(rf) or {}
    return (r.get("judge", {}) or {}).get("result") == "success"


def _surface_success_round(surface_dir: Path):
    for rf in sorted(surface_dir.glob("round_*.json")):
        if _round_success(rf):
            return rf
    return None


def list_playbooks() -> list:
    """All successful attacks across main (Hot100) + compare (SkillInject)."""
    out = []
    # main
    md = _model_dir(MAIN)
    if md:
        for sk in sorted(md.iterdir()):
            if not sk.is_dir() or sk.name.startswith("_"):
                continue
            analyze = _load(sk / f"{sk.name}_analyze.json") or {}
            rt_by_surface = {s.get("id"): s.get("risk_type") for s in analyze.get("results", []) or []}
            title_by_surface = {s.get("id"): s.get("title") for s in analyze.get("results", []) or []}
            for surf in sk.iterdir():
                if not surf.is_dir():
                    continue
                if _surface_success_round(surf):
                    out.append({
                        "source": "main", "dataset": "Hot100",
                        "skill": sk.name, "surface": surf.name,
                        "risk_type": rt_by_surface.get(surf.name) or "",
                        "title": title_by_surface.get(surf.name) or surf.name,
                    })
    # compare (iterative / main side)
    cd = _model_dir(COMP)
    if cd:
        for sk in sorted(cd.iterdir()):
            if not sk.is_dir() or sk.name.startswith("_"):
                continue
            mside = sk / "main"
            if not mside.is_dir():
                continue
            analyze = _load(mside / f"{sk.name}_analyze.json") or {}
            rt_by_surface = {s.get("id"): s.get("risk_type") for s in analyze.get("results", []) or []}
            title_by_surface = {s.get("id"): s.get("title") for s in analyze.get("results", []) or []}
            for surf in mside.iterdir():
                if not surf.is_dir():
                    continue
                if _surface_success_round(surf):
                    out.append({
                        "source": "compare", "dataset": "SkillInject",
                        "skill": sk.name, "surface": surf.name,
                        "risk_type": rt_by_surface.get(surf.name) or "",
                        "title": title_by_surface.get(surf.name) or surf.name,
                    })
    return out


def _skill_src_dir(source: str, skill: str):
    if source == "main":
        d = HOT100 / skill
        return d if d.is_dir() else None
    for split in ("obvious", "contextual"):
        d = INJ / split / skill
        if d.is_dir():
            return d
    return None


def _surface_dir(source: str, skill: str, surface: str):
    if source == "main":
        md = _model_dir(MAIN)
        return md / skill / surface if md else None
    cd = _model_dir(COMP)
    return cd / skill / "main" / surface if cd else None


def _commands(sim: dict) -> list:
    return [(s.get("arguments") or {}).get("command")
            for s in (sim.get("steps") or [])
            if (s.get("arguments") or {}).get("command")]


def _gen_principle(risk: str, title: str, commands: list) -> str:
    base = RISK_PRINCIPLES.get(risk, DEFAULT_PRINCIPLE)
    extra = ""
    if title:
        extra += f"<br><br>本攻擊面「<b>{E(title)}</b>」"
    if commands:
        extra += "：誘導後，agent 實際執行了如下關鍵指令——"
        extra += "<code>" + E(commands[0][:140]) + ("…" if len(commands[0]) > 140 else "") + "</code>"
        extra += "，這正是攻擊得逞的可觀測證據。"
    elif title:
        extra += "。"
    return base + extra


PAGE_CSS = """
:root{--bg:#0f1117;--panel:#191c26;--panel2:#222632;--line:#2c3140;--txt:#e6e8ee;--mut:#9aa3b2;--acc:#5b8cff;--ok:#2ecc71;--warn:#e0a23b;--bad:#ff5d6c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.65 -apple-system,Segoe UI,Roboto,"Noto Sans CJK TC",sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:28px 22px 80px}
a{color:var(--acc)}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:30px 0 10px;border-left:3px solid var(--acc);padding-left:10px}
.badge{display:inline-block;font-size:12px;padding:2px 9px;border-radius:20px;background:rgba(91,140,255,.18);color:var(--acc);font-weight:600;margin-right:6px}
.warn{background:rgba(224,162,59,.12);border:1px solid var(--warn);color:#f0d9a8;border-radius:10px;padding:10px 14px;font-size:13px;margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:10px 0}
pre{background:#0c0e14;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:13px/1.5 ui-monospace,Menlo,monospace;max-height:460px}
code{background:#0c0e14;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font:12px ui-monospace,Menlo,monospace}
.mut{color:var(--mut)}.ok{color:var(--ok)}.step{counter-increment:s;margin:10px 0}.step b{color:var(--acc)}
button.copy{background:var(--panel2);border:1px solid var(--line);color:var(--mut);border-radius:6px;padding:3px 10px;font-size:12px;cursor:pointer;float:right}
details summary{cursor:pointer;color:var(--acc);font-weight:600;margin:8px 0}
.principle{background:linear-gradient(180deg,rgba(91,140,255,.08),transparent);border:1px solid var(--line);border-radius:12px;padding:16px;line-height:1.8}
.filetab{display:inline-block;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:3px 9px;font-size:12px;margin:2px}
"""

JS = """
function cp(id){const e=document.getElementById(id);navigator.clipboard.writeText(e.dataset.raw||e.textContent);}
"""


def render_playbook(source: str, skill: str, surface: str) -> str:
    sdir = _surface_dir(source, skill, surface)
    if not sdir or not sdir.is_dir():
        return "<h1>找不到此攻擊</h1>"
    succ_rf = _surface_success_round(sdir)
    rounds = [(_load(rf) or {}) for rf in sorted(sdir.glob("round_*.json"))]
    succ = _load(succ_rf) or {} if succ_rf else (rounds[-1] if rounds else {})
    atk = succ.get("attack", {}) or {}
    meta = atk.get("metadata") or {}
    tgt = atk.get("target") or {}
    sim = succ.get("simulation", {}) or {}
    jd = succ.get("judge", {}) or {}
    cmds = _commands(sim)
    risk = meta.get("surface_title") and "" or ""
    # risk_type from analyze
    analyze_path = (sdir.parent / f"{(sdir.parent.name if source=='main' else skill)}_analyze.json")
    analyze = _load(analyze_path) or {}
    risk = ""
    title = surface
    for s in analyze.get("results", []) or []:
        if s.get("id") == surface:
            risk = s.get("risk_type") or ""
            title = s.get("title") or surface
            break

    src_dir = _skill_src_dir(source, skill)
    files = []
    if src_dir:
        for f in sorted(src_dir.rglob("*")):
            if f.is_file() and f.stat().st_size < 120_000:
                try:
                    files.append((str(f.relative_to(src_dir)), f.read_text(errors="replace")))
                except Exception:
                    pass

    dataset = "Hot100（真實 skill）" if source == "main" else "SkillInject（對抗 skill）"
    principle = _gen_principle(risk, title, cmds)

    # all prompts (rounds + variants)
    prompt_blocks = ""
    for i, r in enumerate(rounds, 1):
        a = r.get("attack", {}) or {}
        p = a.get("attack_prompt") or ""
        ph = (a.get("metadata") or {}).get("phase") or "-"
        jr = (r.get("judge", {}) or {}).get("result") or "?"
        pid = f"rp{i}"
        prompt_blocks += f"""<details {'open' if r is succ else ''}><summary>Round {r.get('round_id', i)} · phase {E(ph)} · 判定 {E(jr)}{' ✅' if jr=='success' else ''}</summary>
        <pre id="{pid}" data-raw="{E(p)}"><button class="copy" onclick="cp('{pid}')">複製</button>{E(p)}</pre></details>"""

    cmd_block = ""
    if cmds:
        joined = "\n".join("$ " + c for c in cmds)
        cmd_block = f'<pre id="cmds" data-raw="{E(joined)}"><button class="copy" onclick="cp(\'cmds\')">複製</button>{E(joined)}</pre>'
    else:
        cmd_block = '<p class="mut">（此輪未記錄到 exec 指令；攻擊效果體現在 agent 產出的程式碼/內容中，見下方 Judge 證據）</p>'

    file_block = ""
    for idx, (path, content) in enumerate(files):
        file_block += f"""<details {'open' if idx==0 else ''}><summary>📄 {E(path)}</summary>
        <pre id="f{idx}" data-raw="{E(content)}"><button class="copy" onclick="cp('f{idx}')">複製</button>{E(content)}</pre></details>"""
    if not file_block:
        file_block = '<p class="mut">（找不到 skill 原始檔，僅有攻擊面分析）</p>'

    succ_prompt = atk.get("attack_prompt") or ""
    repro = f"""# 1. 進入已建好的隔離沙箱容器
docker exec -it skillrt-openclaw-host bash

# 2. 安裝目標 skill（把下方「三、目標 skill」的檔案放進去）
mkdir -p /root/.openclaw/skills/{E(skill)}
#   將 SKILL.md 與 scripts/ 內容寫入該目錄

# 3. 確認模型已設定（沙箱已由實驗配置 dashscope/qwen；或設你自己的 key）

# 4. 發動攻擊：把「四、攻擊 Prompt」整段送給 agent
openclaw agent --local --session-id repro --verbose on \\
  --message "<貼上攻擊 Prompt 原文>" --json

# 5. 觀察 agent 是否執行了「五、預期 agent 行為」中的指令
# 6. 對照「六、驗證成功」確認攻擊得逞"""

    return f"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>攻擊重現手冊 · {E(skill)}</title><style>{PAGE_CSS}</style><script>{JS}</script></head><body>
<div class="wrap">
  <p class="mut"><a href="javascript:history.back()">← 返回</a></p>
  <span class="badge">{E(dataset)}</span><span class="badge">{E(risk or '—')}</span>
  <h1>🎯 {E(skill)}</h1>
  <p class="mut">攻擊面：{E(title)}　<code>{E(surface)}</code></p>

  <div class="warn">⚠️ 僅供授權的安全研究／紅隊測試與教學使用。請在你自己的隔離環境中操作，勿對未授權系統使用。</div>

  <h2>一、攻擊原理（中文解說）</h2>
  <div class="principle">{principle}</div>

  <h2>二、環境準備</h2>
  <div class="card"><p class="mut">本攻擊在 SkillAttack 的 OpenClaw 隔離沙箱中重現（box2 已建好 <code>skillrt-openclaw-host</code> 容器；--network 受限、SYS_PTRACE，安全）。</p>
  <pre>docker ps --filter name=skillrt-openclaw-host</pre></div>

  <h2>三、目標 skill（安裝 / 操作指示）</h2>
  <div class="card"><p class="mut">把以下檔案放到容器內 <code>/root/.openclaw/skills/{E(skill)}/</code>。SKILL.md 是 agent 會讀取並依其指示操作的「技能說明書」。</p>
  {file_block}</div>

  <h2>四、攻擊 Prompt（送給 agent 的話）</h2>
  <div class="card"><p class="mut ok">▼ 成功攻破的最終 Prompt（直接複製送給 agent）：</p>
  <pre id="succp" data-raw="{E(succ_prompt)}"><button class="copy" onclick="cp('succp')">複製</button>{E(succ_prompt)}</pre>
  <details><summary>展開本攻擊面所有輪次的 Prompt（含多階段精煉過程）</summary>{prompt_blocks}</details></div>

  <h2>五、預期 agent 行為（你應觀察到的指令）</h2>
  <div class="card">{cmd_block}</div>

  <h2>六、驗證成功</h2>
  <div class="card">
  <p><b>成功條件：</b>{E(tgt.get('success_condition') or '—')}</p>
  <p><b>判定（judge）：</b><span class="ok">{E(jd.get('result') or '—')}</span></p>
  <details open><summary>Judge 判定理由（攻擊得逞的證據）</summary><pre>{E(jd.get('reason') or '')}</pre></details>
  </div>

  <h2>七、手動重現步驟</h2>
  <div class="card"><pre id="repro" data-raw="{E(repro)}"><button class="copy" onclick="cp('repro')">複製</button>{E(repro)}</pre></div>

  <h2>八、防禦對應（ClawGuard）</h2>
  <div class="card mut">此類攻擊在執行期會留下可觀測痕跡（讀憑證檔、額外 execve、對外連線、檔案寫入等），對應 ClawGuard 的執行期行為監控偵測點。Prompt 防火牆對「觸發已安裝 skill」型攻擊效果有限，需搭配 L2 程式語意 + L3 執行期行為。</div>
</div></body></html>"""
