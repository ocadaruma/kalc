package com.mayreh.kalc;

import java.util.Arrays;
import java.util.List;

import com.microsoft.z3.Context;
import com.microsoft.z3.EnumSort;
import com.microsoft.z3.Expr;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class TypedEnumSort<T extends Enum<T>> {
    @Getter
    @Accessors(fluent = true)
    private final EnumSort<T> sort;
    private final Class<T> clazz;

    public Expr<EnumSort<T>> getConst(T variant) {
        int idx = Arrays.asList(clazz.getEnumConstants()).indexOf(variant);
        return sort.getConst(idx);
    }

    public static <T extends Enum<T>> TypedEnumSort<T> mkSort(
            Context context, Class<T> clazz, List<T> exclusion) {
        EnumSort<T> sort = context.mkEnumSort(
                clazz.getSimpleName(),
                Arrays.stream(clazz.getEnumConstants())
                      .filter(e -> !exclusion.contains(e))
                      .map(Enum::toString)
                      .toArray(String[]::new));

        return new TypedEnumSort<>(sort, clazz);
    }
}
