package com.mayreh.kalc;

class Utils {
    static String requireNonWildcard(String value) {
        if (AclSpec.WILDCARD.equals(value)) {
            throw new IllegalArgumentException("Wildcard is not allowed");
        }
        return value;
    }

    @SafeVarargs
    static <T> T requireNoneOf(T value, T... excludes) {
        for (T exclude : excludes) {
            if (exclude.equals(value)) {
                throw new IllegalArgumentException(exclude + " is not allowed");
            }
        }
        return value;
    }
}
