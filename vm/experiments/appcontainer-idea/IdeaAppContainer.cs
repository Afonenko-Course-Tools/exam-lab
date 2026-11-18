// Частная проба IDEA, не поставка. Win32 API образец: Microsoft SandboxSecurityTools (MIT).
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Json;
using System.Security.Principal;
class IdeaAppContainer {
    const string IdeaExe="C:\\Program Files\\JetBrains\\IntelliJ IDEA Community Edition 2025.2.6.4\\bin\\idea64.exe";
    [StructLayout(LayoutKind.Sequential)] struct SA { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct GH { public uint Count; public SA First; }
    [StructLayout(LayoutKind.Sequential)] struct SC { public IntPtr Sid,Caps; public uint Count,Reserved; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI {
        public int cb; public string reserved,desktop,title; public uint x,y,xs,ys,xc,yc,fill,flags;
        public short show,cb2; public IntPtr reserved2,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct SIX { public SI si; public IntPtr list; }
    [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public uint pid,tid; }
    static void Check(bool ok) { if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void HR(int value) { if(value<0)Marshal.ThrowExceptionForHR(value); }
    static string SID(IntPtr p) { return p==IntPtr.Zero?null:new SecurityIdentifier(p).Value; }
    static void Emit(string name,Dictionary<string,object> d) {
        d["Event"]=name;d["UTC"]=DateTime.UtcNow.ToString("o");
        using(var m=new MemoryStream()) { new DataContractJsonSerializer(typeof(Dictionary<string,object>),new DataContractJsonSerializerSettings{UseSimpleDictionaryFormat=true,KnownTypes=new Type[]{typeof(string[])}}).WriteObject(m,d);Console.WriteLine(Encoding.UTF8.GetString(m.ToArray())); }
    }
    static IntPtr Query(IntPtr token,int kind) {
        int n;
        if(kind==20||kind==12) n=4; // TOKEN_ELEVATION/TokenSessionId DWORD ABI; native20 length-only error24.
        else { GetTokenInformation(token,kind,IntPtr.Zero,0,out n);if(Marshal.GetLastWin32Error()!=122||n<4||n>65536)throw new Win32Exception(Marshal.GetLastWin32Error()); }
        IntPtr p=Marshal.AllocHGlobal(n);if(!GetTokenInformation(token,kind,p,n,out n)){int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(p);throw new Win32Exception(error);}return p;
    }
    static Dictionary<string,object> Read(IntPtr process,int pid) {
        long born,exited,kernel,user;Check(GetProcessTimes(process,out born,out exited,out kernel,out user));
        var image=new StringBuilder(32768);int length=image.Capacity;Check(QueryFullProcessImageName(process,0,image,ref length));
        IntPtr token;Check(OpenProcessToken(process,8,out token));
        try {
            var d=new Dictionary<string,object>{{"PID",pid},{"BirthUTC",DateTime.FromFileTimeUtc(born).ToString("o")},{"Exe",image.ToString()}};
            foreach(int kind in new int[]{1,12,20,29,31,30}) {
                IntPtr p=Query(token,kind);try {
                    if(kind==1)d["UserSID"]=SID(Marshal.ReadIntPtr(p));
                    if(kind==12)d["Session"]=Marshal.ReadInt32(p);
                    if(kind==20)d["Elevated"]=Marshal.ReadInt32(p)!=0;
                    if(kind==29)d["IsAppContainer"]=Marshal.ReadInt32(p)!=0;
                    if(kind==31)d["AppContainerSID"]=SID(Marshal.ReadIntPtr(p));
                    if(kind==30){int count=Marshal.ReadInt32(p);if(count<0||count>128)throw new Exception("Capability count");var caps=new List<string>();var flags=new List<string>();int offset=(int)Marshal.OffsetOf(typeof(GH),"First"),stride=Marshal.SizeOf(typeof(SA));for(int i=0;i<count;i++){SA row=(SA)Marshal.PtrToStructure(IntPtr.Add(p,offset+i*stride),typeof(SA));caps.Add(SID(row.Sid));flags.Add(SID(row.Sid)+"="+row.Attributes);}caps.Sort(StringComparer.Ordinal);flags.Sort(StringComparer.Ordinal);d["Capabilities"]=caps.ToArray();d["CapabilityAttributes"]=flags.ToArray();}
                } finally {Marshal.FreeHGlobal(p);}
            }
            uint code;Check(GetExitCodeProcess(process,out code));if(code!=259)throw new Exception("Target exited during token capture");return d;
        } finally {CloseHandle(token);}
    }
    static void Gate(Dictionary<string,object> d,string user,int session,bool ac,string package) {
        if((string)d["UserSID"]!=user||(int)d["Session"]!=session||(bool)d["Elevated"]||(bool)d["IsAppContainer"]!=ac)throw new Exception("Actual target identity gate");
        if(ac&&((string)d["AppContainerSID"]!=package||String.Join(";",(string[])d["CapabilityAttributes"])!="S-1-15-3-1=4;S-1-15-3-3=4"))throw new Exception("Actual package/full capability gate");
    }
    static void NoReparse(string path) {
        string p=Path.GetFullPath(path);while(p!=null){if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new Exception("Reparse path "+p);p=Path.GetDirectoryName(p);}
    }
    static string Package(string name) {IntPtr p=IntPtr.Zero;try{HR(DeriveAppContainerSidFromAppContainerName(name,out p));return SID(p);}finally{if(p!=IntPtr.Zero)FreeSid(p);}}
    static string Folder(string package) {IntPtr p=IntPtr.Zero;try{HR(GetAppContainerFolderPath(package,out p));return Marshal.PtrToStringUni(p);}finally{if(p!=IntPtr.Zero)Marshal.FreeCoTaskMem(p);}}
    static string Record(string name,string user,string package) {return name+"\n"+user+"\n"+package+"\n";}
    static string OwnRoot(string name,string user,string package) {
        if(Package(name)!=package)throw new Exception("Profile SID mismatch");string root=Path.Combine(Folder(package),"Temp","IdeaLab");NoReparse(root);
        if(File.ReadAllText(Path.Combine(root,"owned-profile.txt"))!=Record(name,user,package))throw new Exception("Own profile receipt mismatch");return root;
    }
    static void FreshText(string path,string text) {using(var w=new StreamWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read),new UTF8Encoding(false)))w.Write(text);}
    static void Prepare(string name,string user) {
        IntPtr sid=IntPtr.Zero;
        try {HR(CreateAppContainerProfile(name,name,"Private IDEA compatibility probe",IntPtr.Zero,0,out sid));string package=SID(sid),folder=null;
            try{folder=Folder(package);}finally{Emit("ProfileCreated",new Dictionary<string,object>{{"Name",name},{"UserSID",user},{"SID",package},{"Folder",folder},{"ProfileCleanupRequired",true}});}
            NoReparse(folder);string stockTemp=Path.Combine(folder,"Temp");NoReparse(stockTemp);string root=Path.Combine(stockTemp,"IdeaLab");
            if(Directory.Exists(root)||File.Exists(root))throw new Exception("New profile data collision");Directory.CreateDirectory(root);
            foreach(string part in new string[]{"config","system","plugins","log","temp","workspace"})Directory.CreateDirectory(Path.Combine(root,part));
            FreshText(Path.Combine(root,"owned-profile.txt"),Record(name,user,package));
            string properties="";foreach(string part in new string[]{"config","system","plugins","log"})properties+="idea."+part+".path="+Path.Combine(root,part).Replace('\\','/')+"\n";
            FreshText(Path.Combine(root,"idea.properties"),properties);
            Emit("ProfilePrepared",new Dictionary<string,object>{{"Name",name},{"UserSID",user},{"SID",package},{"Folder",folder},{"Root",root},{"RootSDDL",new DirectoryInfo(root).GetAccessControl().GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.All)},{"ProfileCleanupRequired",true}});
        }finally{if(sid!=IntPtr.Zero)FreeSid(sid);}
    }
    static IntPtr Capability(string text) {var sid=new SecurityIdentifier(text);byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);IntPtr p=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,p,bytes.Length);return p;}
    static string Q(string s) {if(s.Contains("\"")||s.EndsWith("\\"))throw new Exception("Unsafe quoted argument");return "\""+s+"\"";}
    static IntPtr EnvironmentBlock(string root) {
        foreach(string key in new string[]{"JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","JDK_JAVAC_OPTIONS","CLASSPATH","IDEA_VM_OPTIONS","IDEA_PROPERTIES","IDEA_JDK"})if(!String.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))throw new Exception("Inherited environment override "+key);
        var vars=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(DictionaryEntry row in Environment.GetEnvironmentVariables())vars[(string)row.Key]=(string)row.Value;
        vars["IDEA_PROPERTIES"]=Path.Combine(root,"idea.properties");vars["TEMP"]=Path.Combine(root,"temp");vars["TMP"]=vars["TEMP"];
        string roaming=Path.Combine(root,"roaming");Directory.CreateDirectory(roaming);NoReparse(roaming);vars["APPDATA"]=roaming;
        var text=new StringBuilder();foreach(var row in vars)text.Append(row.Key).Append('=').Append(row.Value).Append('\0');text.Append('\0');return Marshal.StringToHGlobalUni(text.ToString());
    }
    static void Launch(string name,string user,int session,string package,bool smoke) {
        string root=OwnRoot(name,user,package);if(!smoke)foreach(Process p in Process.GetProcessesByName("idea64")){using(p){throw new Exception("Existing IDEA must exit before launch");}}
        string exe=smoke?Process.GetCurrentProcess().MainModule.FileName:IdeaExe;NoReparse(exe);
        IntPtr sid=IntPtr.Zero,caps=IntPtr.Zero,sc=IntPtr.Zero,list=IntPtr.Zero,env=IntPtr.Zero;IntPtr[] cs={IntPtr.Zero,IntPtr.Zero};PI pi=new PI();bool initialized=false,resumed=false;
        try {HR(DeriveAppContainerSidFromAppContainerName(name,out sid));int stride=Marshal.SizeOf(typeof(SA));caps=Marshal.AllocHGlobal(stride*2);
            for(int i=0;i<2;i++){cs[i]=Capability(i==0?"S-1-15-3-1":"S-1-15-3-3");Marshal.StructureToPtr(new SA{Sid=cs[i],Attributes=4},IntPtr.Add(caps,i*stride),false);}
            sc=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SC)));Marshal.StructureToPtr(new SC{Sid=sid,Caps=caps,Count=2},sc,false);
            IntPtr bytes=IntPtr.Zero;InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);if(Marshal.GetLastWin32Error()!=122)throw new Win32Exception(Marshal.GetLastWin32Error());list=Marshal.AllocHGlobal(bytes);Check(InitializeProcThreadAttributeList(list,1,0,ref bytes));initialized=true;
            Check(UpdateProcThreadAttribute(list,0,(IntPtr)0x20009,sc,(IntPtr)Marshal.SizeOf(typeof(SC)),IntPtr.Zero,IntPtr.Zero));env=EnvironmentBlock(root);
            SIX startup=new SIX();startup.si.cb=Marshal.SizeOf(typeof(SIX));startup.list=list;
            string command=smoke?Q(exe)+" selfwrite "+Q(user)+" "+session+" "+Q(name)+" "+Q(package)+" "+Q(root):Q(exe)+" "+Q(Path.Combine(root,"workspace"));
            Check(CreateProcess(exe,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,0x00080404|(smoke?0x08000000u:0),env,root,ref startup,out pi));
            var evidence=Read(pi.process,(int)pi.pid);Gate(evidence,user,session,true,package);evidence["Profile"]=name;evidence["Root"]=root;evidence["Mode"]=smoke?"smoke":"IDEA";Emit("SuspendedActualToken",evidence);
            if(ResumeThread(pi.thread)==UInt32.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());resumed=true;
            if(smoke){if(WaitForSingleObject(pi.process,20000)!=0)throw new Exception("Smoke child wait exceeded20s; inspect own PID before cleanup");}else Thread.Sleep(1000);
            uint exit;Check(GetExitCodeProcess(pi.process,out exit));Emit("RootAfterResume",new Dictionary<string,object>{{"PID",pi.pid},{"ExitCode",exit},{"Profile",name},{"StillActive",exit==259}});
            if(smoke&&(exit!=0||File.ReadAllText(Path.Combine(root,"workspace","actual-ac-write.txt"))!="actual AppContainer write\n"))throw new Exception("Actual AppContainer write smoke failed");
            if(!smoke){var fresh=Read(pi.process,(int)pi.pid);Gate(fresh,user,session,true,package);Emit("IDEAActualTokenAfterResume",fresh);}
        }finally{if(!resumed&&pi.process!=IntPtr.Zero)TerminateProcess(pi.process,2);if(pi.thread!=IntPtr.Zero)CloseHandle(pi.thread);if(pi.process!=IntPtr.Zero)CloseHandle(pi.process);if(initialized)DeleteProcThreadAttributeList(list);foreach(IntPtr p in new IntPtr[]{caps,sc,list,env,cs[0],cs[1]})if(p!=IntPtr.Zero)Marshal.FreeHGlobal(p);if(sid!=IntPtr.Zero)FreeSid(sid);}
    }
    static void Inspect(string user,int session,string package,int pid,string birth,string exe) {
        IntPtr process=OpenProcess(0x1000,false,pid);if(process==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try{var d=Read(process,pid);if((string)d["BirthUTC"]!=birth||!String.Equals((string)d["Exe"],Path.GetFullPath(exe),StringComparison.OrdinalIgnoreCase))throw new Exception("Target PID birth/exe mismatch");Gate(d,user,session,true,package);Emit("InspectedActualToken",d);}finally{CloseHandle(process);}
    }
    static void Cleanup(string name,string user,int session,string package) {
        string root=OwnRoot(name,user,package);
        foreach(Process p in Process.GetProcesses()){using(p){IntPtr h=OpenProcess(0x1000,false,p.Id);if(h==IntPtr.Zero)continue;try{Dictionary<string,object>d;try{d=Read(h,p.Id);}catch(Win32Exception){continue;}catch(InvalidOperationException){continue;}if((string)d["UserSID"]==user&&(string)d["AppContainerSID"]==package)throw new Exception("Own AppContainer process still alive PID="+p.Id);}finally{CloseHandle(h);}}}
        HR(DeleteAppContainerProfile(name));Emit("ProfileDeleted",new Dictionary<string,object>{{"Name",name},{"SID",package},{"Root",root},{"RequiredExternalEvidence","Export and independent own process-tree exit proof must precede cleanup"}});
    }
    static int Main(string[] a) {
        try {if(a.Length<4)throw new Exception("prepare SID SESSION NAME; smoke|launch|cleanup SID SESSION NAME ACSID; inspect SID SESSION NAME ACSID PID BIRTHUTC EXE");
            string mode=a[0],user=a[1],name=a[3];int session=int.Parse(a[2]);if(!System.Text.RegularExpressions.Regex.IsMatch(name,"^ExamLabIdea-[a-f0-9]{32}$"))throw new Exception("Fresh private profile name required");
            var self=Read(GetCurrentProcess(),Process.GetCurrentProcess().Id);
            if(mode=="selfwrite"){if(a.Length!=6)throw new Exception("selfwrite args");Gate(self,user,session,true,a[4]);string root=a[5];FreshText(Path.Combine(root,"workspace","actual-ac-write.txt"),"actual AppContainer write\n");Emit("ActualAppContainerWrite",self);return 0;}
            Gate(self,user,session,false,null);Emit("CallerActualToken",self);
            if(mode=="prepare"&&a.Length==4)Prepare(name,user);
            else if((mode=="launch"||mode=="smoke")&&a.Length==5)Launch(name,user,session,a[4],mode=="smoke");
            else if(mode=="inspect"&&a.Length==8){OwnRoot(name,user,a[4]);Inspect(user,session,a[4],int.Parse(a[5]),a[6],a[7]);}
            else if(mode=="cleanup"&&a.Length==5)Cleanup(name,user,session,a[4]);
            else throw new Exception("Wrong mode/argument count");return 0;
        }catch(Exception error){
            if(a.Length>0&&a[0]=="selfwrite")try{FreshText(Path.Combine(Environment.GetEnvironmentVariable("TEMP"),"selfwrite-error-"+Process.GetCurrentProcess().Id+".txt"),error.ToString()+"\nHResult="+error.HResult);}catch{}
            Emit("Failure",new Dictionary<string,object>{{"Type",error.GetType().FullName},{"Message",error.Message},{"HResult",error.HResult}});return 2;
        }
    }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr p,out long born,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr p,uint flags,StringBuilder text,ref int size);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint rights,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int kind,IntPtr p,int length,out int required);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr p);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int CreateAppContainerProfile(string name,string display,string description,IntPtr caps,uint count,out IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name,out IntPtr sid);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr bytes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr key,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr ps,IntPtr ts,bool inherit,uint flags,IntPtr env,string cwd,ref SIX startup,out PI info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr p,uint ms);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr p,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint code);
}
