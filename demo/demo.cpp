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

static void increment_twice(int *value, unsigned long long int_1, unsigned long long int_2, unsigned long long int_3, unsigned long long int_4, unsigned long long int_5, unsigned long long int_6)
{
    (*value) = calculate(CALCULATION_TYPE_INCREMENT, (*value));
    (*value) = calculate(CALCULATION_TYPE_INCREMENT, (*value));
}


class other_class {
public:
    other_class() { };
};
    
class some_class {
public:
    some_class() {something = 910; };
    other_class *method();
    int something;
    void __repr__ {
        REPR("FUCK");
    }
};

other_class *some_class::method()
{
    return 0;
}

int main(void) {
    int value = 0;
    const char *some_str = "some variable string which is very very long";
    while (1) {
        increment_twice(&value, 1, 2, 3, 4, 5, 6);
        DEBUG("Oh no");
        WARN(some_str, 100, 150, 100, 100, 100, 100, some_str, 100, 150, 200, 500, 6710, 1021);
        value = calculate(CALCULATION_TYPE_DECREMENT, value);
        usleep(1000000);
    }

    return 0;        
}
