package com.mayreh.kalc;

import java.util.function.Predicate;

class Utils {
    @SafeVarargs
    static <T> T requireNoneOf(T value, T... excludes) {
        for (T exclude : excludes) {
            if (exclude.equals(value)) {
                throw new IllegalArgumentException(exclude + " is not allowed");
            }
        }
        return value;
    }

    static <T> T require(T value, Predicate<T> requirement, String message) {
        if (!requirement.test(value)) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }
}
