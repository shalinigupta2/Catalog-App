# coding: utf-8
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from setup_database import Category, Base, SubItem, User

engine = create_engine('sqlite:///catalogitemswithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Soccer items
category1 = Category(user_id=1, name="Soccer")

session.add(category1)
session.commit()

subItem1 = SubItem(user_id=1, name="Soccer shoes", description="Soccer players should play in turf shoes or cleats,"
                                                               " special footwear made exclusively for soccer "
                                                               "(make sure you don't purchase baseball or football "
                                                               "cleats).These shoes provide better traction on grass, "
                                                               "which increases player's ability to stay on their feet."
                                                               "The footwear material makes kicking a ball painless and"
                                                               " provides some protection against getting stepped on.",
                   category=category1)

session.add(subItem1)
session.commit()

subItem2 = SubItem(user_id=1, name="Soccer socks", description="Soccer socks are extremely long. They cover "
                                                               "shin-guards.",
                   category=category1)
session.add(subItem2)
session.commit()

subItem3 = SubItem(user_id=1, name="Shin-Guards", description="Shin-guards protect player's shins, a vulnerable part "
                                                              "of a player's body that often gets kicked.You should "
                                                              "purchase one at a reasonable size and thickness. "
                                                              "The shinguards should efficiently protect the player's "
                                                              "shins and fit securely in their soccer socks.",
                   category=category1)
session.add(subItem3)
session.commit()

# Basketball
category2 = Category(user_id=1, name="Basketball")

session.add(category2)
session.commit()

subItem1 = SubItem(user_id=1, name="The Ball", description="The most important thing for training is the ball. "
                                                           "There are certain guidelines which one needs to follow when"
                                                           " buying a basketball. For practicing, one can play with a "
                                                           "rubber ball. For professional competitions, one needs to "
                                                           "use an inflated ball made of leather.",
                   category=category2)

session.add(subItem1)
session.commit()


subItem2 = SubItem(user_id=1, name="Basketball Shooting Equipment", description="The hoop or basket is a horizontal "
                                                                                "metallic rim, circular in shape. This "
                                                                                "rim is attached to a net and helps one"
                                                                                " score a point.",
                   category=category2)
session.add(subItem2)
session.commit()

subItem3 = SubItem(user_id=1, name="Backboard", description="The backboard is the rectangular board that is placed "
                                                            "behind the rim. It helps give better rebound to the ball."
                                                            " The backboard is about 1800mm in size horizontally and "
                                                            "1050mm vertically. Many times, backboards are made of "
                                                            "acrylic, aluminum, steel or glass.",
                   category=category2)
session.add(subItem3)
session.commit()

print("Added sub items!")