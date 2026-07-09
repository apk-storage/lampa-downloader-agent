package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

func osExit() { time.Sleep(150 * time.Millisecond); os.Exit(0) }

// startUI serves the local control panel on 127.0.0.1 only.
func (a *Agent) startUI(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.uiIndex)
	mux.HandleFunc("/api/state", a.uiState)
	mux.HandleFunc("/api/opendir", a.uiOpenDir)
	mux.HandleFunc("/api/cancel", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id != "" {
			a.cancelJob(id)
		}
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/api/pickdir", func(w http.ResponseWriter, r *http.Request) {
		d := pickDir()
		if d != "" {
			a.setDir(d)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"dir": a.cfg.DownloadDir})
	})
	mux.HandleFunc("/api/quit", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")); go osExit() })
	go http.ListenAndServe(addr, mux)
}

func (a *Agent) uiState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	jobs := make([]map[string]any, 0, len(a.jobs))
	for _, j := range a.jobs {
		var pct, total, done int64
		if j.t != nil && j.state != "connecting" {
			func() {
				defer func() { _ = recover() }()
				total = j.t.Length()
				done = j.t.BytesCompleted()
			}()
		}
		if total > 0 {
			pct = done * 100 / total
		}
		jobs = append(jobs, map[string]any{
			"id": j.id, "name": j.name, "pct": pct, "state": j.state,
			"done_mib": done / (1 << 20), "total_mib": total / (1 << 20),
		})
	}
	up := a.relayUp
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"code":  fmtCode(a.code),
		"dir":   a.cfg.DownloadDir,
		"seed":  a.cfg.KeepSeeding,
		"relay": up,
		"jobs":  jobs,
	})
}

func (a *Agent) uiOpenDir(w http.ResponseWriter, r *http.Request) {
	openPath(a.cfg.DownloadDir)
	w.Write([]byte("ok"))
}

func openPath(p string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("explorer", p)
	case "darwin":
		cmd = exec.Command("open", p)
	default:
		cmd = exec.Command("xdg-open", p)
	}
	_ = cmd.Start()
}

func (a *Agent) uiIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(panelHTML))
}

const panelHTML = `<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lampa Downloader</title>
<style>
:root{--bg:#1b1b1b;--card:#242424;--soft:#2e2e2e;--line:#333;--text:#f2f2f2;--muted:#8f8f8f;--ok:#5aa15a;--fill:#e8e8e8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:28px;max-width:640px;margin:0 auto}
.top{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.top h1{font-size:18px;font-weight:600;margin:0}
.dot{width:9px;height:9px;border-radius:50%;background:#666}
.dot.on{background:var(--ok)}
.muted{color:var(--muted)}
.card{background:var(--card);border:.5px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px}
.label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px}
.code{display:flex;gap:8px}
.code span{font-family:ui-monospace,Consolas,monospace;font-size:30px;font-weight:600;background:var(--soft);border-radius:8px;padding:6px 14px;letter-spacing:.05em}
.dir{display:flex;align-items:center;gap:10px;margin-top:6px}
.dir .path{font-family:ui-monospace,Consolas,monospace;font-size:13px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:var(--soft);padding:8px 10px;border-radius:8px}
button{background:var(--soft);color:var(--text);border:.5px solid var(--line);border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
button:hover{background:#383838}
.dl{margin:14px 0}
.dl-name{font-size:14px;margin-bottom:6px}
.bar{height:8px;border-radius:4px;background:var(--soft);overflow:hidden}
.fill{height:100%;background:var(--fill);border-radius:4px;transition:width .4s}
.meta{font-size:12px;color:var(--muted);margin-top:5px}
.empty{color:var(--muted);font-size:14px;padding:6px 0}
</style></head><body>
<div class="top"><span class="dot" id="dot"></span><h1>Lampa Downloader</h1><span class="muted" id="relay" style="margin-left:auto;font-size:13px"></span><button onclick="quit()" style="margin-left:14px">Выход</button></div>

<div class="card">
  <div class="label">Код для Лампы</div>
  <div class="code" id="code"></div>
  <div class="muted" style="margin-top:10px;font-size:13px">Введите этот код в Лампе: Настройки → Lampa Downloader → Подключить ПК</div>
</div>

<div class="card">
  <div class="label">Папка загрузок</div>
  <div class="dir"><div class="path" id="dir">—</div><button onclick="openDir()">Открыть</button><button onclick="changeDir()">Изменить</button></div>
</div>

<div class="card">
  <div class="label">Загрузки</div>
  <div id="jobs"><div class="empty">Пока пусто</div></div>
</div>

<script>
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML}
function stateRu(s){return s==='done'?'готово':s==='seeding'?'раздаётся':s==='connecting'?'подключение':'скачивание'}
function openDir(){fetch('/api/opendir')}
function changeDir(){fetch('/api/pickdir').then(r=>r.json()).then(d=>{if(d&&d.dir)document.getElementById('dir').textContent=d.dir}).catch(function(){})}
function cancelJob(id){if(confirm('Отменить эту загрузку?')){fetch('/api/cancel?id='+encodeURIComponent(id)).then(tick)}}
function quit(){if(confirm('Закрыть Lampa Downloader? Загрузки остановятся.')){fetch('/api/quit');document.body.innerHTML='<p style=\"color:#8f8f8f;padding:20px\">Агент остановлен. Можно закрыть окно.</p>'}}
function tick(){
  fetch('/api/state').then(r=>r.json()).then(d=>{
    var code=document.getElementById('code');code.innerHTML='';
    (d.code||'').split(' ').join('').split('').forEach(function(c){var s=document.createElement('span');s.textContent=c;code.appendChild(s)});
    document.getElementById('dir').textContent=d.dir||'—';
    document.getElementById('dot').className='dot'+(d.relay?' on':'');
    document.getElementById('relay').textContent=d.relay?'на связи':'нет связи';
    var box=document.getElementById('jobs');
    if(!d.jobs||!d.jobs.length){box.innerHTML='<div class="empty">Пока пусто</div>';return}
    box.innerHTML=d.jobs.map(function(j){
      var pct=Math.max(0,Math.min(100,j.pct||0));
      return '<div class="dl"><div class="dl-name">'+esc(j.name||('Загрузка '+j.id))+'<button style="float:right;padding:2px 8px;font-size:12px" onclick="cancelJob(\''+esc(j.id)+'\')">✕</button></div>'+
        '<div class="bar"><div class="fill" style="width:'+pct+'%"></div></div>'+
        '<div class="meta">'+stateRu(j.state)+' · '+pct+'% · '+(j.done_mib||0)+'/'+(j.total_mib||0)+' МиБ</div></div>';
    }).join('');
  }).catch(function(){});
}
tick();setInterval(tick,1500);
</script></body></html>`
