import React, { useEffect, useState } from 'react';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import { useNavigate } from 'react-router-dom';
import Cookies from 'js-cookie';

const AppLayout = ({ children }) => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const getToken = Cookies.get('token');
        if (!getToken) {
            navigate('/login');
        } else {
            setLoading(false);
        }
    }, [navigate]);

    if (loading) {
        return null; // Or a loading spinner component
    }

    return (
        <div className='bg-white'>
            <Navbar />
            <div className=' w-screen flex container mx-auto' style={{ height: 'calc(100vh - 56px)' }}>
                <div className="w-[220px]">
                    <Sidebar />
                </div>
                <div className="flex-1">
                    <div className="flex">
                        {children}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default AppLayout;
