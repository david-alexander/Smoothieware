#ifndef CALLBACKSTREAM_H
#define CALLBACKSTREAM_H

typedef int (*cb_t)(const char *, void *);
typedef int (*getc_cb_t)(void *);

#ifdef __cplusplus
#include "libs/StreamOutput.h"


class CallbackStream : public StreamOutput {
    public:
        CallbackStream(cb_t cb, void *u);
        CallbackStream(cb_t cb, getc_cb_t getc_cb, void *u);
        virtual ~CallbackStream();
        int puts(const char*);
        int _getc(void);
        void inc() { use_count++; }
        void dec();
        int get_count() { return use_count; }
        void mark_closed();

    private:
        cb_t callback;
        getc_cb_t getc_callback;
        void *user;
        bool closed;
        int use_count;
};

#else

extern void *new_callback_stream(cb_t cb, getc_cb_t getc_cb, void *);
extern void delete_callback_stream(void *);
extern void call_idle();

#endif // __cplusplus

#endif
