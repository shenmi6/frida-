
console.log("shenmi");

/*
 * 进程级访问监视（MemoryAccessMonitor）
 *  - 跨所有线程，不依赖 per-thread 硬件断点
 *  - details.from 就是"发起访问的那条指令 PC"
 *  - 按页触发，抓完一次要重新 enable（本脚本已自动重挂）
 *  - 抓到 maxHits 次或超时后彻底关闭，不留后台
 */
var CFG = {
    targetAddress: "0x6FACF0D2E0",   // 你的地址
    maxHits: 50000,                      // 抓几次就收工
    giveUpMs: 300000000,                 // 超时放弃
    reenabelDelayMs: 30,             // 每次命中后重挂的延迟
};

function log(m) {
    console.log(m);
    try { send(m); } catch (e) { }
}

function hex(n) { return "0x" + Number(n).toString(16); }

function locate(p) {
    try {
        var m = Process.findModuleByAddress(p);
        if (m) return m.name + "+" + hex(parseInt(p.toString(), 16) - parseInt(m.base.toString(), 16));
    } catch (e) { }
    return "(anon)";
}

var T = ptr(CFG.targetAddress);
var PAGE = T.and(ptr(Process.pageSize - 1).not());
var PAGE_END = PAGE.add(Process.pageSize);

var hits = 0;
var active = false;
var rearming = false;
var timer = null;

function readVal() {
    try { return T.readU32().toString(); } catch (e) { return "?"; }
}

function shutdown(reason) {
    active = false;
    if (timer) { clearTimeout(timer); timer = null; }
    try { MemoryAccessMonitor.disable(); } catch (e) { }
    log("[v13] 监视已关闭（" + reason + "），脚本静止");
}

function armMonitor() {
    if (!active) return;
    try {
        MemoryAccessMonitor.enable({ base: PAGE, size: Process.pageSize }, {
            onAccess: function (d) {
                if (!active) return;
                hits++;

                var from = null, addr = null, op = d.operation;
                try { from = d.from; } catch (e) { }
                try { addr = d.address; } catch (e) { }

                var loc = "?", insn = "?";
                try { if (from) loc = locate(from); } catch (e) { }
                try { if (from) insn = Instruction.parse(from).toString(); } catch (e) { }

                log("");
                log("====== 第 " + hits + " 次访问 ======");
                log(" 操作   : " + op);
                log(" 访问点 : " + (from ? from.toString() : "?") + "  [" + loc + "]");
                log(" 指令   : " + insn);
                log(" 地址   : " + (addr ? addr.toString() : "?"));
                log(" 当前值 : " + readVal());
                log(" 线程   : " + (function () { try { return Process.getCurrentThreadId(); } catch (e) { return "?"; } })());
                log("======================");

                // 页保护已被改回，需要重挂才能抓下一次
                if (hits >= CFG.maxHits) {
                    shutdown("已抓到 " + CFG.maxHits + " 次");
                    return;
                }
                if (rearming) return;
                rearming = true;
                setTimeout(function () {
                    rearming = false;
                    if (!active) return;
                    armMonitor();
                }, CFG.reenabelDelayMs);
            }
        });
    } catch (e) {
        log("[v13] enable 失败: " + e.message);
        if (e.message && e.message.indexOf("unable to protect") >= 0) {
            log("[v13] 该页无法改保护属性（可能是特殊映射），硬件断点以外的方案也用不了");
        }
        shutdown("enable 异常");
    }
}

function main() {
    log("[v13] pid=" + Process.id + " arch=" + Process.arch);
    log("[v13] target=" + T + "  page=" + PAGE + " - " + PAGE_END);
    var r = null;
    try { r = Process.findRangeByAddress(T); } catch (e) { }
    if (!r) { log("[v13] 地址未映射，先重新搜"); return; }
    log("[v13] range=" + r.base + "-" + r.base.add(r.size) + " prot=" + r.protection);
    log("[v13] 当前值=" + readVal() + " 位置=" + locate(T));
    log("[v13] maxHits=" + CFG.maxHits + " giveUpMs=" + CFG.giveUpMs);

    active = true;
    armMonitor();
    log("[v13] 监视已开启（进程级，跨线程）");

    timer = setTimeout(function () {
        if (!active) return;
        log("[v13] " + CFG.giveUpMs + "ms 内没有任何访问");
        log("[v13] 结论：这个地址确实没被读写 → 它是死副本，或值来自别处");
        shutdown("超时无访问");
    }, CFG.giveUpMs);
}

main();
