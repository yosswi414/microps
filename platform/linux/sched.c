#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "platform.h"

int sched_ctx_init(struct sched_ctx *ctx){
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

int sched_ctx_destroy(struct sched_ctx *ctx){
    // 条件変数の破棄 (待機中のスレッドが存在する場合のみエラー)
    return pthread_cond_destroy(&ctx->cond);   
}

int sched_sleep(struct sched_ctx *ctx, mutex_t* mutex, const struct timespec *abstime){
    int ret;

    if(ctx->interrupted){
        errno = EINTR;
        return -1;
    }
    ++ctx->wc;
    /*  pthread_cond_broadcast() が呼ばれるまでスレッド休止
     *  abstime が指定されていれば指定時刻に起床する pthread_cond_timedwait() を使用
     *  (休止する際は mutex が unlock され、起床する際に lock された状態で戻ってくる)
     */
    ret = abstime ? pthread_cond_timedwait(&ctx->cond, mutex, abstime)
                  : pthread_cond_wait(&ctx->cond, mutex);
    --ctx->wc;

    if(ctx->interrupted){
        // 休止中だったスレッド全てが起床したら interrupted フラグをクリア
        if (!ctx->wc) ctx->interrupted = 0;
        errno = EINTR;
        return -1;
    }
    return ret;
}

int sched_wakeup(struct sched_ctx *ctx){
    return pthread_cond_broadcast(&ctx->cond);  // 休止しているスレッドを起床させる
}

int sched_interrupt(struct sched_ctx *ctx){
    // interrupted フラグをセットして休止スレッドを起床
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}