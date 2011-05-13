package com.proofpoint.experimental.units;

import com.google.common.base.Preconditions;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Math.floor;

public class DataSize
        implements Comparable<DataSize>
{
    private static final Pattern PATTERN = Pattern.compile("^\\s*(\\d+(?:\\.\\d+)?)\\s*([a-zA-Z]+)\\s*$");

    private final double value;
    private final Unit unit;

    public DataSize(double size, Unit unit)
    {
        Preconditions.checkArgument(!Double.isInfinite(size), "size is infinite");
        Preconditions.checkArgument(!Double.isNaN(size), "size is not a number");
        Preconditions.checkArgument(size >= 0, "size is negative");
        Preconditions.checkNotNull(unit, "unit is null");

        this.value = size;
        this.unit = unit;
    }

    public double getValue()
    {
        return value;
    }

    public Unit getUnit()
    {
        return unit;
    }

    public double getValue(Unit unit)
    {
        return value * (this.unit.getFactor() * 1.0 / unit.getFactor());
    }

    public DataSize convertTo(Unit unit)
    {
        return new DataSize(getValue(unit), unit);
    }

    public String toString()
    {
        if (floor(value) == value) {
            return (long) (floor(value)) + unit.getUnitString();
        }

        return value + unit.getUnitString();
    }

    public static DataSize valueOf(String size)
            throws IllegalArgumentException
    {
        Preconditions.checkNotNull(size, "size is null");
        Preconditions.checkArgument(!size.isEmpty(), "size is empty");

        Matcher matcher = PATTERN.matcher(size);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("size is not a valid data size string: " + size);
        }

        double value = Double.parseDouble(matcher.group(1));
        String unitString = matcher.group(2);

        for (Unit unit : Unit.values()) {
            if (unit.getUnitString().equals(unitString)) {
                return new DataSize(value, unit);
            }
        }

        throw new IllegalArgumentException("Unknown unit: " + unitString);
    }

    @Override
    public int compareTo(DataSize o)
    {
        return Double.compare(getValue(Unit.BYTE), o.getValue(Unit.BYTE));
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        DataSize dataSize = (DataSize) o;

        return compareTo(dataSize) == 0;
    }

    @Override
    public int hashCode()
    {
        double value = getValue(Unit.BYTE);

        long temp = value != 0d ? Double.doubleToLongBits(value) : 0L;
        return (int) (temp ^ (temp >>> 32));
    }

    public enum Unit
    {
        BYTE(1L, "B"),
        KILOBYTE(1L << 10, "kB"),
        MEGABYTE(1L << 20, "MB"),
        GIGABYTE(1L << 30, "GB"),
        TERABYTE(1L << 40, "TB"),
        PETABYTE(1L << 50, "PB");

        private final long factor;
        private final String unitString;

        Unit(long factor, String unitString)
        {
            this.factor = factor;
            this.unitString = unitString;
        }

        long getFactor()
        {
            return factor;
        }

        String getUnitString()
        {
            return unitString;
        }
    }
}
