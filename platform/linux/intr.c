#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

struct irq_entry {
    struct irq_entry* next;
    unsigned int irq;
    int (*handler)(unsigned int irq, void* dev);
    int flags;
    char name[16];
    void* dev;
};

// You need to protect the lists with mutex if you add/delete entries after intr_run()
static struct irq_entry* irqs;

static sigset_t sigmask;  // シグナルマスク用のシグナル集合

static pthread_t tid;  // 割り込みスレッドのスレッド ID
static pthread_barrier_t barrier;   // スレッド間の同期のためのバリア

// 割り込みハンドラの登録
int intr_request_irq(
    unsigned int irq,
    int (*handler)(unsigned int irq, void *dev),
    int flags,
    const char* name,
    void* dev
){
    struct irq_entry* entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);

    // IRQ 番号が既に登録されている場合、IRQ 番号の共有が許可されているかどうかチェック
    // どちらかが共有を許可していない場合 (共有フラグの競合) はエラーを返す
    for (entry = irqs; entry; entry = entry->next){
        if(entry->irq == irq){
            if(entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED){
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    // IRQ リストへ新たなエントリを追加
    entry = memory_alloc(sizeof(*entry));
    if(!entry){
        errorf("memory_alloc() failed");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;

    // シグナル集合へ新たなシグナルを追加
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);
    return 0;
}

// 割り込みの発生
int intr_raise_irq(unsigned int irq){
    return pthread_kill(tid, (int)irq); // 割り込み処理スレッドへシグナル送信
}

static int intr_timer_setup(struct itimerspec *interval){
    timer_t id;

    if(timer_create(CLOCK_REALTIME, NULL, &id) == -1){
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }
    if(timer_settime(id, 0, interval, NULL) == -1){
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// 割り込みの捕捉と振り分け
static void* intr_thread(void* arg){
    const struct timespec ts = {0, 1000000};    // 1 ms
    struct itimerspec interval = {ts, ts};
    int terminate = 0, sig, err;
    struct irq_entry* entry;

    debugf("start...");
    pthread_barrier_wait(&barrier); // メインスレッドと同期をとる

    // 周期処理用タイマーセットアップ
    if(intr_timer_setup(&interval) == -1){
        errorf("intr_timer_setup() failed");
        return NULL;
    }

    while(!terminate){
        // 割り込みに見立てたシグナルが発生するまで待機
        err = sigwait(&sigmask, &sig);
        if(err){
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch(sig) {
            // SIGHUP: 割り込みスレッドへ終了を通知するシグナル
            case SIGHUP:
                terminate = 1;
                break;
            // SIGUSR1: ソフトウェア割り込み用
            case SIGUSR1:
                net_softirq_handler();
                break;
            // SIGALRM: 周期処理用タイマー発火時用
            case SIGALRM:
                net_timer_handler();
                break;
            // IRQ リストを巡回し、IRQ 番号が一致するエントリのハンドラを呼び出す
            default:
                for (entry = irqs; entry;entry=entry->next){
                    if(entry->irq == (unsigned int)sig){
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

// 割り込み機構の起動
int intr_run(void) {
    int err;
    // シグナルマスクの設定
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if(err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    // 割り込み処理スレッドの起動
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if(err){
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }

    // スレッドが動き出すまで待つ
    // 他のスレッドが同様に pthread_barrier_wait() を呼び出し、
    // 呼び出し回数がバリアのカウントに達するまでスレッドを停止
    pthread_barrier_wait(&barrier);
    return 0;
}

// 割り込み機構の停止
void intr_shutdown(void) {
    // 割り込み処理スレッドが起動済か確認
    if(pthread_equal(tid, pthread_self()) != 0){
        // Thread has not been created
        return;
    }
    pthread_kill(tid, SIGHUP);  // 割り込み処理スレッドに SIGHUP を送信
    pthread_join(tid, NULL);    // 割り込み処理スレッドが完全に終了するのを待つ
}

// 割り込み機構の初期化
int intr_init(void){
    tid = pthread_self();   // スレッド ID の初期値にメインスレッドの ID を設定
    pthread_barrier_init(&barrier, NULL, 2);    // 2 回呼ばれるまでスレッドを停止するバリア
    sigemptyset(&sigmask);  // シグナル集合の初期化 (空)
    sigaddset(&sigmask, SIGHUP);    // 割り込みスレッド終了通知用に SIGHUP を追加
    sigaddset(&sigmask, SIGUSR1);   // ソフトウェア割り込み用
    sigaddset(&sigmask, SIGALRM);   // 周期処理用タイマー発火時用
    return 0;
}
