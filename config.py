
ROOT_FOLDER = "./"

Init_Assert_Function = ["RtlRaiseStatus","HalReturnToFirmware","KiDispatchException","RtlDispatchException","ExRaiseAccessViolation",
"ZwRaiseException","KiBugCheckDebugBreak","xHalHaltSystem","KeBugCheck","KeBugCheckEx","__report_gsfailure","__report_rangecheckfailure","DbgBreakPoint","DbgUserBreakPoint","DbgBreakPointWithStatus",
"KiUserApcDispatcher","KiUserCallbackDispatcher","ExRaiseDatatypeMisalignment"]

Binary_Path = "./binary_file/"

error_address = 18446744073709551615

IDA_PATH = "" # to ida.exe

DB_NAME  = ROOT_FOLDER + "static_analysis.db"

prompt_file = ROOT_FOLDER + "request.yaml"


Slicing_LOG_PATH = ROOT_FOLDER + "log\\slicing\\log.txt"
save_dir = ROOT_FOLDER + "slicings"