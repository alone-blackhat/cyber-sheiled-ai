import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import BlackWolfAI from "./components/BlackWolfAI.tsx";
import "./index.css";

const blackWolfEl = document.getElementById("black-wolf-react-root");
if (blackWolfEl) {
  createRoot(blackWolfEl).render(
    <StrictMode>
      <BlackWolfAI />
    </StrictMode>
  );
}
