
N = 0   # The number of registers in the register list to be loaded or stored, including PC or LR
P = 0   # The number of cycles required for a pipline refill.
        # This ranges from 1 to 3 depending on the alignment and width of the target instruction, and whether the processor manages to speculate the address early
B = 0   # The number of cycles required to perform the barrier operation. For DSB and DMB, the minumum number of cycles is zero. For ISB, the minimum number of cycles is equivalent to the number required for a pipeline refill
W = 0   # The number of cycles spent waiting for an appropriate event



div_num = {2,3,4,5,6,7,8,9,10,11,12}
total_cycle = 0

MOVE = {"mov" : 1, "movw" : 1, "movt" : 1}
ADD = {"add" : 1, "adc" : 1, "adr" : 1}
SUB = {"sub" : 1, "sbc" : 1, "rsb" : 1}
MUL = {"mul" : 1, "mla" : 2, "mls" : 2, "smulld" : 1, "umull" : 1, "SMLAL" : 1, "UMLAL" : 1}
DIV = {"SDIV" : div_num, "UDIV" : div_num}
SATURATE = {"SSAT" : 1, "USAT" : 1}
COMPARE = {"CMP" : 1, "CMN" : 1}
LOGICAL = {"AND" : 1, "EOR" : 1, "ORR" : 1, "ORN" : 1, "BIC" : 1, "MVN" : 1, "TST" : 1, "TEQ" : 0}
SHIFT = {"LSL" : 1, "LSR" : 1, "ASR" : 1}
ROTATE = {"ROR" : 1, "RRX" : 1}
COUNT = {"CLZ" : 1}
LOAD = {"ldr" : 2, "ldrh" : 2, "ldrb" : 2, "ldrsh" : 2, "ldrsb" : 2, "ldrt" : 2, "ldrht" : 2, "ldrbt" : 2, "ldrsht": 2, "ldrsbt" : 2,
        "ldrd" : 1 + N, "ldm" : 1 + N}
STORE = {"str" : 2, "strh" : 2,"strb" : 2,"strsh" : 2,"strsb": 2, "strt" : 2, "strht": 2, "strbt": 2, "strsht": 2, "strsbt": 2, "strd": 1 + N, "STM": 2}
PUSH = {"push" : 1 + N}
POP = {"pop" : 1 + N}
SEMAPHORE = {"LDREX" : 2, "LDREXH" : 2 , "LDREXB" : 2 , "STREX" : 2 , "STREXH" : 2 , "STREXB" : 2 , "CLREX" : 1}
BRANCH = {"b" : 1 + P, "bl" : 1 + P, "bx" : 1 + P, "blx" : 1 + P, "cbz" : 1 + P, "cbnz" : 1 + P, "tbb" : 2 + P, "tbh" : 2 + P}
STATE_CHANGE = {"svc" : 0, "it" : 1, "cpsid" : 1}
#State change
#Extend
#Bit field
#Reverse
#Hint
#Barriers

def cycle_cal(ins):
    str_head = "".join(list(ins)[0:2])

    if str_head == "pu":
        return PUSH[ins]
    elif str_head == "mo":
        return MOVE[ins]
    elif str_head == "su":
        return SUB[ins]
    elif str_head == "ld":
        return LOAD[ins]
    elif str_head == "st":
        return STORE[ins]
    


    