import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import ScanDetails from "./pages/ScanDetails";
import ScanDiff from "./pages/ScanDiff";
import ThreatIntelligence from "./pages/ThreatIntelligence";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/:id" element={<ScanDetails />} />
        <Route path="/diff" element={<ScanDiff />} />
        <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
