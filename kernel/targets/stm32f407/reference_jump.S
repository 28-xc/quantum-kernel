.syntax unified
.cpu cortex-m4
.thumb
.text
.global setjmp
.type setjmp,%function
.thumb_func
setjmp:
 stmia r0!,{r4-r11}
 mov r1,sp
 str r1,[r0]
 str lr,[r0,#4]
 movs r0,#0
 bx lr
.global longjmp
.type longjmp,%function
.thumb_func
longjmp:
 ldmia r0!,{r4-r11}
 ldr r2,[r0]
 mov sp,r2
 ldr lr,[r0,#4]
 movs r0,r1
 it eq
 moveq r0,#1
 bx lr
