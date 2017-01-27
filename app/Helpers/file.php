<?php
if ( ! function_exists('byte_format')) {

    function byte_format($num, $precision = 1)
    {
        if ($num >= 1000000000000) {
            $num = round($num / 1099511627776, $precision);
            $unit = 'TB';
        } elseif ($num >= 1000000000) {
            $num = round($num / 1073741824, $precision);
            $unit = 'GB';
        } elseif ($num >= 1000000) {
            $num = round($num / 1048576, $precision);
            $unit = 'MB';
        } elseif ($num >= 1000) {
            $num = round($num / 1024, $precision);
            $unit = 'KB';
        } else {
            $unit = 'B';

            return number_format($num) . ' ' . $unit;
        }

        return number_format($num, $precision) . ' ' . $unit;
    }
}