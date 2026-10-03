import "./Card.css";

const Card = ({title, para})=> {
    return (
        <div className="card">
            <h4>{title}</h4>
            <p>{para}</p>
        </div>
    );
}

export default Card;