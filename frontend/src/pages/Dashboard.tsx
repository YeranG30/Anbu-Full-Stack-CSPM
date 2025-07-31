import { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Activity,
  TrendingUp,
  TrendingDown,
  CheckCircle,
  XCircle,
  Lock,
  Eye,
  UserCheck
} from 'lucide-react';

// Core CSPM data - focused on the three main features
const coreSecurityData = {
  iamSecurity: {
    aws: { secure: 145, violations: 23, total: 168, trend: -8 },
    gcp: { secure: 89, violations: 12, total: 101, trend: -5 },
    azure: { secure: 76, violations: 8, total: 84, trend: -12 }
  },
  dataExposure: {
    s3Buckets: { secure: 234, exposed: 8, total: 242 },
    gcpStorage: { secure: 156, exposed: 3, total: 159 },
    azureBlobs: { secure: 89, exposed: 2, total: 91 }
  },
  privilegeCompliance: {
    leastPrivilege: 78,
    zeroTrust: 85,
    privilegeEscalation: 15,
    trend: 5
  }
};

const SecurityMetricCard = ({ title, value, subtitle, trend, status, icon: Icon }) => {
  const getStatusColor = () => {
    switch (status) {
      case 'critical': return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950';
      case 'warning': return 'border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950';
      case 'success': return 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950';
      default: return 'border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800';
    }
  };

  const getIconColor = () => {
    switch (status) {
      case 'critical': return 'text-red-600 dark:text-red-400';
      case 'warning': return 'text-amber-600 dark:text-amber-400';
      case 'success': return 'text-green-600 dark:text-green-400';
      default: return 'text-gray-600 dark:text-gray-400';
    }
  };

  return (
    <div className={`border rounded-xl p-6 ${getStatusColor()} transition-all duration-300 hover:shadow-lg`}>
      <div className="flex items-center justify-between mb-4">
        <Icon className={`h-7 w-7 ${getIconColor()}`} />
        {trend && (
          <div className={`flex items-center space-x-1 text-sm font-bold ${
            trend > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'
          }`}>
            {trend > 0 ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
            <span>{Math.abs(trend)}%</span>
          </div>
        )}
      </div>
      <div className="space-y-2">
        <h3 className="text-3xl font-black text-gray-900 dark:text-white tabular-nums">{value}</h3>
        <p className="text-sm font-bold text-gray-700 dark:text-gray-300 tracking-wide">{title}</p>
        {subtitle && (
          <p className="text-xs text-gray-500 dark:text-gray-400 font-medium">{subtitle}</p>
        )}
      </div>
    </div>
  );
};

const IAMSecurityChart = () => {
  const { iamSecurity } = coreSecurityData;
  
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center space-x-3 mb-2">
          <Shield className="h-6 w-6 text-blue-600 dark:text-blue-400" />
          <h3 className="text-xl font-black text-gray-900 dark:text-white tracking-tight">IAM SECURITY STATUS</h3>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400 font-bold tracking-wide">AWS IAM • GCP ROLES • AZURE POLICIES</p>
      </div>
      <div className="p-6">
        <div className="space-y-8">
          {Object.entries(iamSecurity).map(([cloud, data]) => (
            <div key={cloud} className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-3">
                  <span className="text-sm font-black text-gray-700 dark:text-gray-300 tracking-wider uppercase">
                    {cloud}
                  </span>
                  <div className={`flex items-center space-x-1 text-xs font-bold ${
                    data.trend < 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
                  }`}>
                    {data.trend < 0 ? <TrendingDown className="h-3 w-3" /> : <TrendingUp className="h-3 w-3" />}
                    <span>{Math.abs(data.trend)}%</span>
                  </div>
                </div>
                <div className="flex items-center space-x-6 text-xs font-mono">
                  <span className="text-green-600 dark:text-green-400 font-bold">SECURE: {data.secure}</span>
                  <span className="text-red-600 dark:text-red-400 font-bold">VIOLATIONS: {data.violations}</span>
                </div>
              </div>
              
              <div className="relative">
                <div className="flex h-8 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden shadow-inner">
                  <div 
                    className="bg-gradient-to-r from-green-400 to-green-500 transition-all duration-1000 ease-out"
                    style={{ width: `${(data.secure / data.total) * 100}%` }}
                    title={`Secure: ${data.secure}`}
                  />
                  <div 
                    className="bg-gradient-to-r from-red-400 to-red-500 transition-all duration-1000 ease-out"
                    style={{ width: `${(data.violations / data.total) * 100}%` }}
                    title={`Violations: ${data.violations}`}
                  />
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-xs font-black text-white mix-blend-difference">
                    {Math.round((data.secure / data.total) * 100)}% COMPLIANT
                  </span>
                </div>
              </div>
              
              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
                  <div className="text-lg font-black text-gray-900 dark:text-white tabular-nums">{data.total}</div>
                  <div className="text-xs font-bold text-gray-500 dark:text-gray-400 tracking-wider">TOTAL</div>
                </div>
                <div className="bg-green-50 dark:bg-green-950 rounded-lg p-3">
                  <div className="text-lg font-black text-green-600 dark:text-green-400 tabular-nums">{data.secure}</div>
                  <div className="text-xs font-bold text-green-600 dark:text-green-400 tracking-wider">SECURE</div>
                </div>
                <div className="bg-red-50 dark:bg-red-950 rounded-lg p-3">
                  <div className="text-lg font-black text-red-600 dark:text-red-400 tabular-nums">{data.violations}</div>
                  <div className="text-xs font-bold text-red-600 dark:text-red-400 tracking-wider">ISSUES</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const DataExposureChart = () => {
  const { dataExposure } = coreSecurityData;
  const totalExposed = Object.values(dataExposure).reduce((sum, data) => sum + data.exposed, 0);
  const totalBuckets = Object.values(dataExposure).reduce((sum, data) => sum + data.total, 0);
  
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center space-x-3 mb-2">
          <Eye className="h-6 w-6 text-red-600 dark:text-red-400" />
          <h3 className="text-xl font-black text-gray-900 dark:text-white tracking-tight">DATA EXPOSURE DETECTION</h3>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400 font-bold tracking-wide">OVEREXPOSED STORAGE BUCKETS</p>
      </div>
      <div className="p-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="text-center bg-gray-50 dark:bg-gray-900 rounded-xl p-4">
            <div className="text-2xl font-black text-gray-900 dark:text-white tabular-nums">{totalBuckets}</div>
            <div className="text-xs font-bold text-gray-500 dark:text-gray-400 tracking-wider">TOTAL BUCKETS</div>
          </div>
          <div className="text-center bg-green-50 dark:bg-green-950 rounded-xl p-4">
            <div className="text-2xl font-black text-green-600 dark:text-green-400 tabular-nums">{totalBuckets - totalExposed}</div>
            <div className="text-xs font-bold text-green-600 dark:text-green-400 tracking-wider">SECURE</div>
          </div>
          <div className="text-center bg-red-50 dark:bg-red-950 rounded-xl p-4">
            <div className="text-2xl font-black text-red-600 dark:text-red-400 tabular-nums">{totalExposed}</div>
            <div className="text-xs font-bold text-red-600 dark:text-red-400 tracking-wider">EXPOSED</div>
          </div>
        </div>

        {/* Individual Storage Types */}
        <div className="space-y-6">
          {Object.entries(dataExposure).map(([storage, data]) => {
            const exposureRate = (data.exposed / data.total) * 100;
            const storageLabel = storage.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
            
            return (
              <div key={storage} className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-black text-gray-700 dark:text-gray-300 tracking-wider">
                    {storageLabel}
                  </span>
                  <div className="flex items-center space-x-4 text-xs font-mono">
                    <span className="text-green-600 dark:text-green-400 font-bold">SECURE: {data.secure}</span>
                    <span className="text-red-600 dark:text-red-400 font-bold">EXPOSED: {data.exposed}</span>
                  </div>
                </div>
                
                <div className="relative">
                  <div className="flex h-6 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div 
                      className="bg-gradient-to-r from-green-400 to-green-500 transition-all duration-1000"
                      style={{ width: `${(data.secure / data.total) * 100}%` }}
                    />
                    <div 
                      className="bg-gradient-to-r from-red-400 to-red-500 transition-all duration-1000"
                      style={{ width: `${(data.exposed / data.total) * 100}%` }}
                    />
                  </div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-xs font-black text-white mix-blend-difference">
                      {exposureRate.toFixed(1)}% EXPOSED
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

const PrivilegeComplianceChart = () => {
  const { privilegeCompliance } = coreSecurityData;
  
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <UserCheck className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            <div>
              <h3 className="text-xl font-black text-gray-900 dark:text-white tracking-tight">PRIVILEGE ENFORCEMENT</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 font-bold tracking-wide">LEAST PRIVILEGE • ZERO TRUST</p>
            </div>
          </div>
          <div className={`flex items-center space-x-1 text-sm font-bold ${
            privilegeCompliance.trend > 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'
          }`}>
            {privilegeCompliance.trend > 0 ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
            <span>{Math.abs(privilegeCompliance.trend)}%</span>
          </div>
        </div>
      </div>
      <div className="p-6">
        <div className="space-y-8">
          {/* Least Privilege */}
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-black text-gray-700 dark:text-gray-300 tracking-wider">
                LEAST PRIVILEGE COMPLIANCE
              </span>
              <span className="text-xl font-black text-green-600 dark:text-green-400 tabular-nums">
                {privilegeCompliance.leastPrivilege}%
              </span>
            </div>
            <div className="relative">
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-6">
                <div 
                  className="h-6 bg-gradient-to-r from-green-400 to-green-500 rounded-full transition-all duration-1000 shadow-sm"
                  style={{ width: `${privilegeCompliance.leastPrivilege}%` }}
                />
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xs font-black text-white mix-blend-difference">
                  {privilegeCompliance.leastPrivilege}% COMPLIANT
                </span>
              </div>
            </div>
          </div>
          
          {/* Zero Trust */}
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-black text-gray-700 dark:text-gray-300 tracking-wider">
                ZERO TRUST IMPLEMENTATION
              </span>
              <span className="text-xl font-black text-blue-600 dark:text-blue-400 tabular-nums">
                {privilegeCompliance.zeroTrust}%
              </span>
            </div>
            <div className="relative">
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-6">
                <div 
                  className="h-6 bg-gradient-to-r from-blue-400 to-blue-500 rounded-full transition-all duration-1000 shadow-sm"
                  style={{ width: `${privilegeCompliance.zeroTrust}%` }}
                />
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xs font-black text-white mix-blend-difference">
                  {privilegeCompliance.zeroTrust}% IMPLEMENTED
                </span>
              </div>
            </div>
          </div>
          
          {/* Privilege Escalation Risks */}
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-black text-gray-700 dark:text-gray-300 tracking-wider">
                PRIVILEGE ESCALATION RISKS
              </span>
              <span className="text-xl font-black text-red-600 dark:text-red-400 tabular-nums">
                {privilegeCompliance.privilegeEscalation} ACTIVE
              </span>
            </div>
            <div className="grid grid-cols-10 gap-1">
              {Array.from({ length: 20 }, (_, i) => (
                <div 
                  key={i}
                  className={`h-4 rounded transition-all duration-500 ${
                    i < privilegeCompliance.privilegeEscalation 
                      ? 'bg-gradient-to-t from-red-400 to-red-500 shadow-sm' 
                      : 'bg-gray-200 dark:bg-gray-700'
                  }`}
                  style={{ transitionDelay: `${i * 100}ms` }}
                />
              ))}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 font-mono text-center">
              RISK LEVEL: {privilegeCompliance.privilegeEscalation <= 5 ? 'LOW' : privilegeCompliance.privilegeEscalation <= 10 ? 'MEDIUM' : 'HIGH'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default function FocusedCSPMDashboard() {
  const [isDark, setIsDark] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    setTimeout(() => setIsLoading(false), 1200);
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setIsDark(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  const toggleDark = () => {
    setIsDark(!isDark);
    document.documentElement.classList.toggle('dark');
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-16 w-16 border-4 border-gray-300 border-t-blue-600 mx-auto"></div>
            <Shield className="absolute inset-0 m-auto h-6 w-6 text-blue-600 animate-pulse" />
          </div>
          <p className="mt-6 text-sm font-bold text-gray-600 dark:text-gray-400 tracking-wide">
            INITIALIZING SECURITY DASHBOARD...
          </p>
        </div>
      </div>
    );
  }

  const totalViolations = Object.values(coreSecurityData.iamSecurity).reduce((sum, data) => sum + data.violations, 0);
  const totalExposed = Object.values(coreSecurityData.dataExposure).reduce((sum, data) => sum + data.exposed, 0);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800" style={{ fontFamily: '"Inter", "Segoe UI", "Helvetica Neue", Arial, sans-serif' }}>
      {/* Header */}
      <header className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-b border-gray-200 dark:border-gray-700 sticky top-0 z-10">
        <div className="px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
                <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h1 className="text-2xl font-black text-gray-900 dark:text-white tracking-tight">
                  CLOUD SECURITY POSTURE MANAGEMENT
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400 font-bold tracking-widest">
                  CORE SECURITY FEATURES • REAL-TIME MONITORING
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-xs text-gray-500 dark:text-gray-400 font-mono">LAST UPDATED</div>
                <div className="text-sm font-bold text-gray-700 dark:text-gray-300">2 MIN AGO</div>
              </div>
              <button 
                onClick={toggleDark}
                className="p-3 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-xl transition-all duration-200"
              >
                {isDark ? '☀️' : '🌙'}
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="px-8 py-8">
        <div className="max-w-7xl mx-auto space-y-8">
          {/* Key Metrics Overview */}
          <section>
            <h2 className="text-lg font-black text-gray-900 dark:text-white mb-6 tracking-wide">SECURITY OVERVIEW</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <SecurityMetricCard
                title="IAM Violations"
                value={totalViolations}
                subtitle="Identity & access issues"
                trend={-8}
                status="warning"
                icon={Shield}
              />
              <SecurityMetricCard
                title="Exposed Data Stores"
                value={totalExposed}
                subtitle="Overexposed storage buckets"
                trend={-15}
                status="critical"
                icon={AlertTriangle}
              />
              <SecurityMetricCard
                title="Privilege Compliance"
                value={`${coreSecurityData.privilegeCompliance.leastPrivilege}%`}
                subtitle="Least privilege adherence"
                trend={5}
                status="success"
                icon={Activity}
              />
            </div>
          </section>

          {/* Core Security Features */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
            {/* IAM Security - spans full width on large screens */}
            <div className="xl:col-span-2">
              <IAMSecurityChart />
            </div>
            
            {/* Data Exposure and Privilege Enforcement side by side */}
            <DataExposureChart />
            <PrivilegeComplianceChart />
          </div>
        </div>
      </main>
    </div>
  );
}