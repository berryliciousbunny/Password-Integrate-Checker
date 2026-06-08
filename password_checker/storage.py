# storage.py
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    note = Column(String, default='')


def init_db(path='sqlite:///passwords.db'):
    engine = create_engine(path, echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# tiny helpers

def add_user(Session, username: str, password_hash: str, note: str = ''):
    session = Session()
    u = User(username=username, password_hash=password_hash, note=note)
    session.add(u)
    session.commit()
    session.close()


def get_all_users(Session):
    session = Session()
    users = session.query(User).all()
    session.close()
    return users


def find_user(Session, username: str):
    session = Session()
    u = session.query(User).filter_by(username=username).first()
    session.close()
    return u
