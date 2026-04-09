import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ApiProvider } from './context/ApiContext';
import { AnalysisResultProvider } from './context/AnalysisResultContext';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ApiProvider>
      <AnalysisResultProvider>
        <App />
      </AnalysisResultProvider>
    </ApiProvider>
  </React.StrictMode>,
);
