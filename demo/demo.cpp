#include <unistd.h>
#include <stdio.h>
#include "trace_user.h"
enum calculation_type {
    CALCULATION_TYPE_DECREMENT,
    CALCULATION_TYPE_INCREMENT,
};

int calculate(enum calculation_type e, int value) {
   INFO("Calculation type:", e);
   if (e == CALCULATION_TYPE_DECREMENT) {
       return value - 1;
   } else if (e == CALCULATION_TYPE_INCREMENT) {
       return value + 1;
   }

   return -1;
}

static void increment_twice(int *value)
{
    (*value) = calculate(CALCULATION_TYPE_INCREMENT, (*value));
    (*value) = calculate(CALCULATION_TYPE_INCREMENT, (*value));
}


class some_class {
public:
    some_class() {something = 910; };
    int something;
    void __repr__ {
        REPR("some_class(", something, ")");
    }
};

int main(void) {
    some_class the_class_ptr;
    int value = 0;
    const char *some_str = "some variable string which is very very long";
    while (1) {
        increment_twice(&value);
        WARN(some_str, 100, 150, &the_class_ptr, 100, 100, 100, 100, some_str, 100, 150, 200, 500, 6710, 1021);
        value = calculate(CALCULATION_TYPE_DECREMENT, value);
        usleep(10000);
    }

    return 0;        
}
