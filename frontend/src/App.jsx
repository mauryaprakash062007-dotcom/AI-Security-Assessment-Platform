import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import ScanDetails from "./pages/ScanDetails";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/:id" element={<ScanDetails />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
