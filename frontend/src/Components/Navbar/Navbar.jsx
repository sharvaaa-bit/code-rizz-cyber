import { Link } from "react-router-dom";
import "./Navbar.css";

const Navbar = () => {
  return (
    <nav>
        <h1>ADAPTIVE AUTONOMOUS XDR</h1>
        <ul>
            <li><Link to="/">Home</Link></li>
            <li><Link to="#features">About</Link></li>
            <li><Link to="/contact">Contact</Link></li>
        </ul>
    </nav>
  );
};

export default Navbar;