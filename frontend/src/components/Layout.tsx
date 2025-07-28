// src/layouts/MainLayout.tsx

import Sidebar from "../components/Sidebar";
import { Outlet } from "react-router-dom";

export default function MainLayout() {
  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 bg-gray-50 p-8 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
