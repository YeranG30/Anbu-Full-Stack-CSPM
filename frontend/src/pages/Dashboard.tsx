export default function Dashboard() {
  const stats = [
    { label: "IAM Findings", value: 14, color: "bg-red-100 text-red-700" },
    { label: "Public Buckets", value: 3, color: "bg-yellow-100 text-yellow-700" },
    { label: "Unencrypted DBs", value: 5, color: "bg-blue-100 text-blue-700" },
    { label: "CI/CD Risks", value: 2, color: "bg-purple-100 text-purple-700" },
  ];

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Cloud Security Dashboard</h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
          <div
            key={stat.label}
            className={`rounded-xl p-6 shadow-md ${stat.color}`}
          >
            <div className="text-sm font-medium">{stat.label}</div>
            <div className="text-2xl font-bold mt-2">{stat.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
