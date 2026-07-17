import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import ScanDetails from "./pages/ScanDetails";
import ScanDiff from "./pages/ScanDiff";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/:id" element={<ScanDetails />} />
        <Route path="/diff" element={<ScanDiff />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
