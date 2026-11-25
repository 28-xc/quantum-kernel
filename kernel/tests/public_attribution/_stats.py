"""Two-sided Student t probabilities for the fixed-block replay (NumPy only).

The regularized incomplete beta uses its convergent continued fraction with
the complementary tail selected at (a+1)/(a+b+2). Results are checked against
the archived SciPy statistics for every published contrast.
"""
import math
import numpy as np
def fraction(a,b,x):
 qab=a+b;qap=a+1;qam=a-1;c=1.;d=1-qab*x/qap
 tiny=1e-300
 if abs(d)<tiny:d=tiny
 d=1/d;h=d
 for m in range(1,10001):
  m2=2*m;aa=m*(b-m)*x/((qam+m2)*(a+m2));d=1+aa*d
  if abs(d)<tiny:d=tiny
  c=1+aa/c
  if abs(c)<tiny:c=tiny
  d=1/d;h*=d*c
  aa=-(a+m)*(qab+m)*x/((a+m2)*(qap+m2));d=1+aa*d
  if abs(d)<tiny:d=tiny
  c=1+aa/c
  if abs(c)<tiny:c=tiny
  d=1/d;delta=d*c;h*=delta
  if abs(delta-1)<3e-15:return h
 raise ArithmeticError('Incomplete beta convergence failed')
def beta(a,b,x):
 if x<=0:return 0.
 if x>=1:return 1.
 front=math.exp(math.lgamma(a+b)-math.lgamma(a)-math.lgamma(b)+a*math.log(x)+b*math.log1p(-x))
 return front*fraction(a,b,x)/a if x<(a+1)/(a+b+2) else 1-front*fraction(b,a,1-x)/b
def ttest_1samp(values,mean):
 values=np.asarray(values,dtype=float);n=len(values);df=n-1
 t=float((values.mean()-mean)/np.sqrt(values.var(ddof=1)/n))
 p=beta(df/2,.5,df/(df+t*t))
 return t,p
