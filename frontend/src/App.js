import AppLayout from "./components/AppLayout";
import { Routes, Route } from "react-router-dom";
import Task from "./components/Task";
import { Toaster } from "react-hot-toast";
import Login from "./components/Login";
import SignUp from "./components/SignUp";
import Home from "./components/Home";


function App() {
  return (
    <>
      <Toaster position="top-right" gutter={8} />
      <Routes>
        <Route path="/" element={<AppLayout><Home /></AppLayout>} />
        <Route path="/:projectId" element={<AppLayout><Task /></AppLayout>} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />
      </Routes>
    </>
  );
}

export default App;
