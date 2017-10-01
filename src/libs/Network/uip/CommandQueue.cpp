#include "CommandQueue.h"

#include "stdio.h"
#include "string.h"
#include "stdlib.h"

#include "Kernel.h"
#include "libs/SerialMessage.h"
#include "CallbackStream.h"
#include "Network.h"

static CommandQueue *command_queue_instance;
CommandQueue *CommandQueue::instance = NULL;


CommandQueue::CommandQueue()
{
    command_queue_instance = this;
    null_stream= &(StreamOutput::NullStream);
}

CommandQueue* CommandQueue::getInstance()
{
    if(instance == 0) instance= new CommandQueue();
    return instance;
}

extern "C" {
    void network_handle_console_line(char const* str, void* pstream)
    {
        struct SerialMessage message;
        message.message = str;
        message.stream = (StreamOutput*)pstream;

        THEKERNEL->call_event(ON_CONSOLE_LINE_RECEIVED, &message );
    }

    void network_pump_command_queue()
    {
        //command_queue_instance->pop();
    }

    int network_add_command(const char *cmd, void *pstream)
    {
        int result = command_queue_instance->add(cmd, (StreamOutput*)pstream);
        appcall_on_next_idle = true;
        return result;
    }
}

int CommandQueue::add(const char *cmd, StreamOutput *pstream)
{
    cmd_t c= {strdup(cmd), pstream==NULL?null_stream:pstream};
    q.push(c);
    if(pstream != NULL) {
        // count how many times this is on the queue
        CallbackStream *s= static_cast<CallbackStream *>(pstream);
        s->inc();
    }
    return q.size();
}

// pops the next command off the queue and submits it.
bool CommandQueue::pop()
{
    if (q.size() == 0) return false;

    cmd_t c= q.pop();
    char *cmd= c.str;

    struct SerialMessage message;
    message.message = cmd;
    message.stream = c.pstream;

    free(cmd);
    THEKERNEL->call_event(ON_CONSOLE_LINE_RECEIVED, &message );

    if(message.stream != null_stream) {
        message.stream->puts(NULL); // indicates command is done
        // decrement usage count
        CallbackStream *s= static_cast<CallbackStream *>(message.stream);
        s->dec();
    }
    return true;
}
