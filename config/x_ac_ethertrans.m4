AC_DEFUN([X_AC_ETHERTRANS], [

AC_ARG_ENABLE([ethertrans],
  [AS_HELP_STRING([--enable-ethertrans], [build Xen Ethernet transport])],
  [want_ethertrans=yes], [want_ethertrans=no])

if test x$want_ethertrans == xyes; then
  got_ethertrans=yes
  AC_DEFINE([WITH_ETHERTRANS], [1], [build Xen Ethernet transport])
fi

AM_CONDITIONAL([ETHERTRANS], [test "x$got_ethertrans" != xno])

])
