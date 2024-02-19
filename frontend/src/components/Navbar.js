import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Cookies from 'js-cookie';

const Navbar = () => {
  const navigate = useNavigate();
  const handleLogout = () => {
    // Remove the token cookie

    Cookies.remove('token');
    navigate('/login');

    // You can add any additional logout logic here, such as redirecting to the login page
  };

  return (
    <div className='bg-white shadow h-14 flex items-center justify-between px-4'>
      <div className='text-lg font-semibold'>Logo</div>
      <div className='flex items-center'>
        <Link to='/' className='mr-4 text-blue-500 hover:text-blue-700'>Home</Link>
        <button onClick={handleLogout} className='px-3 py-1 bg-blue-500 text-white rounded-md hover:bg-blue-600'>Logout</button>
      </div>
    </div>
  );
}

export default Navbar;
