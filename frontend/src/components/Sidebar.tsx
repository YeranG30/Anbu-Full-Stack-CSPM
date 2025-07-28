
import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, Settings } from "lucide-react";

const navItems = [
  { name: "Dashboard", path: "/", icon: <LayoutDashboard size={20} /> },
  { name: "Settings", path: "/settings", icon: <Settings size={20} /> },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <div className="w-64 bg-white shadow-md flex flex-col">
      <div className="px-6 py-4 text-2xl font-bold border-b">SecureCSPM</div>
      <nav className="flex-1 p-4">
        {navItems.map((item) => (
          <Link
            key={item.name}
            to={item.path}
            className={`flex items-center gap-3 px-4 py-2 mb-2 rounded-lg text-sm font-medium transition-all ${
              location.pathname === item.path
                ? "bg-blue-100 text-blue-600"
                : "text-gray-700 hover:bg-gray-100"
            }`}
          >
            {item.icon}
            {item.name}
          </Link>
        ))}
      </nav>
    </div>
  );
}
