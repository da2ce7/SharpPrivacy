using System;
using System.Collections;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.ServiceProcess;
using System.Configuration.Install;
using System.Threading;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;

namespace WindowsService {
	/// <summary>
	/// This is the class for my Service
	/// </summary>
	public class SharpPrivacySrv : System.ServiceProcess.ServiceBase {
		
		private HttpChannel myChannel;
		
		public SharpPrivacySrv() {
			InitializeComponents();
		}
		
		private void InitializeComponents() {
			this.ServiceName = "SharpPrivacySrv";
		}
		
		/// <summary>
		/// This method starts the service.
		/// </summary>
		public static void Main() {
			System.ServiceProcess.ServiceBase.Run(new System.ServiceProcess.ServiceBase[] {
				new SharpPrivacySrv() // To run more than one service you have to add them here
			});
		}

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		protected override void Dispose(bool disposing) {
			// TODO: Add cleanup code here (if required)
			base.Dispose(disposing);
		}

		/// <summary>
		/// Start this service.
		/// </summary>
		protected override void OnStart(string[] args) {
	        myChannel = new HttpChannel(4433);
	 
	        ChannelServices.RegisterChannel(myChannel);
		    RemotingConfiguration.RegisterWellKnownServiceType(typeof(SharpPrivacy.SharpPrivacySrv.SharpPrivacy), "SharpPrivacy", WellKnownObjectMode.Singleton);
			
	        EventLog.WriteEntry ("SharpPrivacySrv: Service started successfully");
		}
 
		/// <summary>
		/// Stop this service.
		/// </summary>
		protected override void OnStop() {
			ChannelServices.UnregisterChannel(myChannel);
		}

	}
}

[RunInstaller(true)]
public class ProjectInstaller : Installer {
    public ProjectInstaller() {
        ServiceProcessInstaller spi = new ServiceProcessInstaller();
        spi.Account = ServiceAccount.LocalSystem;

        ServiceInstaller si = new ServiceInstaller();
    	si.DisplayName = "SharpPrivacy OpenPGP Service";
        si.ServiceName = "SharpPrivacySrv";
        si.StartType = ServiceStartMode.Automatic;
    	
        Installers.AddRange(new Installer[] {spi, si});
    }
}
