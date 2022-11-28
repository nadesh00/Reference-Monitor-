# Implement a Defensive Security System

This assignment is intended to reinforce concepts about access control and
reference monitors in a hands-on manner. 

## Overview
----
In this assignment you will create a security layer which will always left indent 
after the '\n' newline character in a write that strictly appends to a file.   By 
"strictly appends", this means the first byte of the write is at the current end 
of file (after the last previously written data).  This is something that is 
sometimes done by a document editors, when they believe you have ended a paragraph.  
For this assignment, the '\n' character is treated as a newline and other characters 
(notably '\r') are not treated specially.

You should write test applications to ensure your reference monitor behaves properly 
in different cases and to test attacks against your monitor.    

#### The Reference Monitor Must:
1. Behave identically to a non-sandboxed program [RepyV2 API calls](../Programming/RepyV2API.md) for
   all calls other than a writeat()s that strictly append.  So other writeat()s, readat()s, etc. 
        must be performed as they would in a non-sandboxed program!
2. If a writeat() strictly appends to a file, then:
   * If it contains no '\n' characters, perform the writeat() operation normally (as a non-sandboxed program)
   * If it contains exactly one '\n' character, then perform a writeat() that strictly appends, 
     but with four space ' ' characters inserted after the '\n'.   
   * If it contains more than one '\n' character, raise a RepyArgumentError exception
3. Not produce any errors or output for any reason except as mentioned above  
   * Normal operations should not be blocked or produce any output  
   * Invalid operations should not produce any output to the user
4. Not call readat() everytime writeat() is called.  This will be too slow and is forbidden.


Three design paradigms are at work in this assignment: accuracy,
efficiency, and security.

 * Accuracy: The security layer should only modify certain operations (a strictly
appending writeat() with one '\n') and raise an exception for certain other 
actions (a strictly appending writeat() with more than one '\n'). All situations 
that are not described above *must* match that of the underlying API.

 * Efficiency: The security layer should use a minimum number of resources,
so performance is not compromised.  For example, you may not call readat() 
everytime writeat() is called.  It is permissable to call readat() upon fileopen(),
however.

 * Security: The attacker should not be able to circumvent the security
layer. For example, if the attacker can cause a non-strictly appending write to
have '    ' inserted after '\n' or can cause the reference monitor to incorrectly
error or hang, then the security is compromised.


## Building the security layer
----
The following program is a sample security layer, it is not complete and does not 
handle all cases required by the API. Remember, you have no idea how the
attacker will try to penetrate your security layer, so it is important that
you leave nothing to chance!  


### A basic (and inadequate) defense

Time to start coding!  Let's inspect a basic security layer.  

```
"""
This security layer inadequately handles LeftPad writeat()s that strictly append



Note:
    This security layer uses encasementlib.r2py, restrictions.default, repy.py and Python
    Also you need to give it an application to run.
    python repy.py restrictions.default encasementlib.r2py [security_layer].r2py [attack_program].r2py 
    
    """ 
TYPE="type"
ARGS="args"
RETURN="return"
EXCP="exceptions"
TARGET="target"
FUNC="func"
OBJC="objc"

class LPFile():
  def __init__(self,filename,create):
    # globals
    mycontext['debug'] = False   
    self.LPfile = openfile(filename,create)
    self.length = 0

  def readat(self, bytes, offset):
    # Read from the file using the sandbox's readat...
    return self.LPfile.readat(bytes, offset)

  def writeat(self,data,offset):
    if not offset == self.length:
      # write the data and update the length (BUG?)
      self.LPfile.writeat(data,offset)
      self.length = offset + len(data)

    else:
    
      if '\n' not in data:
        self.LPfile.writeat(data,offset)
      else: # bug?
        loc = data.find('\n')
        # bug?
        self.LPfile.writeat(data[:loc]+"    "+data[loc:],offset)

  
  def close(self):
    self.LPfile.close()


def LPopenfile(filename, create):
  return LPFile(filename,create)




# The code here sets up type checking and variable hiding for you.  You
# should not need to change anything below here.
sec_file_def = {"obj-type":LPFile,
                "name":"LPFile",
                "writeat":{"type":"func","args":(str,(int,long)),"exceptions":Exception,"return":(int,type(None)),"target":LPFile.writeat},
                "readat":{"type":"func","args":((int,long,type(None)),(int,long)),"exceptions":Exception,"return":str,"target":LPFile.readat},
                "close":{"type":"func","args":None,"exceptions":Exception,"return":(bool,type(None)),"target":LPFile.close}
           }

CHILD_CONTEXT_DEF["openfile"] = {TYPE:OBJC,ARGS:(str,bool),EXCP:Exception,RETURN:sec_file_def,TARGET:LPopenfile}

# Execute the user code
secure_dispatch_module()
```



### Testing your security layer
----
In this part of the assignment you will pretend to be an attacker. Remember
the attacker's objective is to bypass the A/B restrictions or cause
the security layer to act in a disallowed manner. By understanding how the
attacker thinks, you will be able to write better security layers.  

An example of an attack is found below:

```
# clean up if the file exists.
if "testfile.txt" in listfiles():
  removefile("testfile.txt")

myfile=openfile("testfile.txt",True)  #Create a file

myfile.writeat("12345678",0) # no difference, no '\n'

myfile.writeat("Hi!",0) # writing early in the file

myfile.writeat("Append!\nShould be indented!!!",8) # strictly appending...

assert(' ' == myfile.readat(1,17)) # this location should contain a space...

#Close the file
myfile.close()


```

If the reference monitor is correct, there should be no assertion failure...

**Note:** All attacks should be written as Repy V2 files, using the .r2py extension.

