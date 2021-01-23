

const arm64CM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);
static void on_arm64_after(GumCpuContext *cpu_context, gpointer user_data);

typedef struct CalloutUserData {
    cs_insn *insn;
    GumCpuContext *prev_cpu_context;
} CalloutUserData;


typedef struct TransformUserData {
    guint16 tid;
    gpointer start;
    gpointer end;
} TransformUserData;

typedef struct TraceTidCtx {
    TransformUserData transform_user_data;
    
} TraceTidCtx;


void hello() {
    on_message("Hello form CModule");
}


static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}

void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    TransformUserData *tranf_ud = (TransformUserData*) user_data;
    guint16 tid = tranf_ud->tid;
    gpointer start = tranf_ud->start;
    gpointer end = tranf_ud->end;

    gboolean first_ins_in_block = TRUE;

    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= start && (gpointer)insn->address < end;
        if(in_target && first_ins_in_block)
        {
            // gum_stalker_iterator_put_callout(iterator, on_arm64_before, (gpointer) insn, NULL);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            // branch not call
            // gum_stalker_iterator_put_callout(iterator, on_arm64_after, (gpointer) insn, NULL);
        }
        first_ins_in_block = FALSE;
    }
}


GumCpuContext prev_cpu_context = {0};

static void
on_arm64_before(GumCpuContext *cpu_context,
    gpointer user_data)
{
    // cs_insn *insn = (gpointer) user_data;
    // log("%p\t%s\t%s", insn->address, insn->mnemonic, insn->op_str);
    // memcpy(&prev_cpu_context, cpu_context, sizeof(GumCpuContext));
}

static void
on_arm64_after(GumCpuContext *cpu_context,
    gpointer user_data)
{
    log("after pc:%p", cpu_context->pc);
}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)

      }, 'void', ['pointer']),
});


const userData = Memory.alloc(Process.pageSize);
const pointerSize = Process.pointerSize;
function stalkerTraceRangeC(tid, base, size) {
    // const hello = new NativeFunction(cm.hello, 'void', []);
    // hello();
    var udPtr = userData;
    udPtr.writeU16(tid);
    udPtr = udPtr.add(pointerSize);
    udPtr.writePointer(base);
    udPtr = udPtr.add(pointerSize);
    udPtr.writePointer(base.add(size));
    
    Stalker.follow(tid, {
        transform: arm64CM.transform,
        // onEvent: cm.process,
        data: userData /* user_data */
    })
}


function traceAddr(addr) {
    let moduleMap = new ModuleMap();    
    let targetModule = moduleMap.find(addr);


    console.log(addr)

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId()
            console.log(this.tid)
            stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size)
        },
        onLeave: function(ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect()
            send({
                type: "fin",
                tid: this.tid
            })
        }
    })
}


(()=> {
    console.log('loading ...')
    const symbol = "test";
    const libname = "libnative-lib.so"
    const targetModule = Process.getModuleByName(libname);
    console.log(JSON.stringify(targetModule))
    let targetAddress = targetModule.findExportByName(symbol);
    traceAddr(targetAddress)
})()

