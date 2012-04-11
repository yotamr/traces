#include <unistd.h>
#include <stdio.h>

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

int main(void) {
    int value = 0;
    while (1) {
        value = calculate(CALCULATION_TYPE_DECREMENT, value);
        increment_twice(&value);
        WARN("Next iteration", value);
        usleep(10000);
    }

    return 0;        
}
