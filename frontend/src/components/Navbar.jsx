import React from 'react';
import { useSelector, useDispatch } from "react-redux";
import { login, logout } from "../redux/slices/authSlice"
import { motion } from 'framer-motion';
import { Link, useNavigate } from "react-router-dom";
import { singlePageLinks } from "../lib/data/navbar-single-page-data";
import { useTheme } from "../context/ThemeContext";
import { useActiveSection } from '../context/ActiveSectionContext';

const Navbar = () => {
    const { theme, toggleTheme } = useTheme();
    const { activeSection, setActiveSection, setTimeOfLastClick} = useActiveSection();
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const isAuthenticated = useSelector((state) => state.auth.isAuthenticated);

    // const handleRegisterClick = () => {
    //     navigate('/register');
    // };

    // const handleLoginClick = () => {
    //     navigate('/login');
    // };

    const toggleAuth = () => {
        if (isAuthenticated) dispatch(logout())
        else dispatch(login())
    }

    return (
        <header className="z-[999] relative">
            <motion.div
                className="fixed top-0 left-1/2 h-[4.5rem] w-full rounded-none border border-white border-opacity-40 bg-white bg-opacity-80 shadow-lg shadow-black/[0.03] backdrop-blur-[0.5rem] sm:top-6 sm:h-[3.25rem] sm:w-[36rem] sm:rounded-full dark:bg-gray-950 dark:border-black/40 dark:bg-opacity-75"
                initial={{ y: -100, x: "-50%", opacity: 0 }}
                animate={{ y: 0, x: "-50%", opacity: 1 }}
            >
            </motion.div>

            <nav className="flex fixed top-[0.15rem] left-1/2 h-12 -translate-x-1/2 py-2 sm:top-[1.7rem] sm:h-[initial] sm:py-0">
                <ul className="flex w-[22rem] flex-wrap items-center justify-center gap-y-1 text-[0.9rem] font-medium text-gray-500 sm:w-[initial] sm:flex-nowrap sm:gap-5">
                    {singlePageLinks.map((link) => (
                        <motion.li
                        className="h-3/4 flex items-center justify-center relative"
                        key={link.hash}
                        initial={{ y: -100, opacity: 0 }}
                        animate={{ y: 0, opacity: 1 }}
                        >
                        <Link
                            className={
                            `flex w-full items-center justify-center px-3 py-3 hover:text-gray-950 transition dark:text-gray-500 dark:hover:text-gray-300
                            ${activeSection === link.name ? "text-gray-950 dark:text-gray-100" : ""}`}
                            to={`/${link.hash}`} 
                            onClick={() => {
                            setActiveSection(link.name);
                            setTimeOfLastClick(Date.now());
                            }}
                        >
                            {link.name}

                            {link.name === activeSection && (
                            <motion.span
                                className="bg-gray-200 rounded-full absolute inset-0 -z-10 dark:bg-gray-800"
                                layoutId="activeSection"
                                transition={{
                                type: "spring",
                                stiffness: 380,
                                damping: 30,
                                }}
                            ></motion.span>
                            )}
                        </Link>
                        </motion.li>
                    ))}
                    {/* <div className="flex gap-4 mx-5">
                                    <a onClick={handleLoginClick} className="text-white dark:text-gray-300 text-xl cursor-pointer">Login</a>
                                    <a onClick={handleRegisterClick} className="text-white dark:text-gray-300 text-xl cursor-pointer">Register</a>
                                </div> */}
                </ul>
            </nav>
            <div onClick={toggleAuth} className='absolute right-[100px] top-[35px] cursor-pointer'>{isAuthenticated ? "authenticated" : "not authenticated"}</div>
        </header>
    );
}

export default Navbar;