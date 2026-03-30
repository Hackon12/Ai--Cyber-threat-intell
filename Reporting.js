import React, { useState, useEffect } from 'react';
import axios from 'axios';

const Reporting = () => {
    const [reportData, setReportData] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');

    const fetchReport = async () => {
        setIsLoading(true);
        setError('');
        try {
            const response = await axios.get('/api/dashboard-data');
            setReportData(response.data);
        } catch (err) {
            setError('Failed to generate report. Please try again later.');
            console.error('Error fetching report data:', err);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        // Fetch initial data on component mount
        fetchReport();
    }, []);

    return (
        <div className="reporting-container">
            <h3>System Report</h3>
            <button onClick={fetchReport} disabled={isLoading}>
                {isLoading ? 'Generating...' : 'Generate Full Report'}
            </button>

            {error && <p className="error-message">{error}</p>}

            {reportData && (
                <div className="report-summary">
                    <h4>Report Summary</h4>
                    <ul>
                        <li><strong>Active Nodes:</strong> {reportData.graph?.nodes?.length || 0}</li>
                        <li><strong>Network Links:</strong> {reportData.graph?.links?.length || 0}</li>
                        <li><strong>Tracked Packets:</strong> {reportData.packets?.length || 0}</li>
                        <li><strong>IPv4 IOCs:</strong> {reportData.iocs['ipv4-addr']?.length || 0}</li>
                        <li><strong>Domain IOCs:</strong> {reportData.iocs['domain']?.length || 0}</li>
                    </ul>
                </div>
            )}
        </div>
    );
};

export default Reporting;