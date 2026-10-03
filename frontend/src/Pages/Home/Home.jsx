import {BrowserRouter, Link} from 'react-router-dom'
import Navbar from '../../Components/Navbar/Navbar';
import Card from '../../Components/Card/Card';

import "./Home.css";
const Home = ()=>{ 
    return (
        <div className="home">
            <Navbar />

        <header className="container">
          <div className="content">
            <span className="blur"></span>
            <span className="blur"></span>
            <h4>TO ENHANCE YOUR PROTECTION</h4>
            <h1>ADAPTIVE AUTONOMOUS XDR</h1>
            <p>Protect your organization with our advanced threat detection and response capabilities.</p>
            <Link to="/dashboard" className='btn'>Get Started</Link>
          </div>
          <div className="image">
            <img src="https://www.facilitiesnet.com/resources/editorial/2023/businessman-on-blurred-background-using-antivirus-sstock_617737619.jpg"
             alt="Header Image"/>
          </div>
        </header>

        <section className="container">
          <h2 className='header'><span className='blur'/>Features<span className='blur'/></h2>
            <div className="features">
                <Card 
                    title='Adaptive Anomaly Detection'
                    para='Identifies unusual behavior in security telemetry instead of relying only on known attack patterns.'
                    logo=''/>
                <Card 
                    title='Intelligent Threat Correlation & Risk Analysis'
                    para='Connects related suspicious events, evaluates their combined evidence, and calculates a risk score and severity.'
                    logo=''/>
                <Card 
                    title='Autonomous Incident Response & SOC Dashboard'
                    para='Converts detected threats into structured incidents and gives security teams a centralized view for investigation and defensive response.'
                    logo=''/>
            </div>
          </section>
        </div>
    );
}

export default Home;