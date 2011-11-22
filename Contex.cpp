
#include "Context.h"

Context* Context::currentContext_ = 0;

Context::Context()
{
    parentContext_ = currentContext_;
    currentContext_ = this;
}
    
Context::~Context()
{
    currentContext_ = parentContext_;
}
