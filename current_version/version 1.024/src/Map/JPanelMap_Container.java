package Map;

import javax.swing.*;
import Driver.*;
import java.awt.*;

public class JPanelMap_Container extends JPanel
{
	public static final String myClassName = "JPanelMap_Container";
	public static volatile Driver driver = new Driver();
	
	//JScrollPane jscrlpne = null;
	WEB_COMPONENT component = null;
	
	public JPanelMap_Container(String load_path)
	{
		try
		{
			this.setLayout(new BorderLayout());
			
			component = new WEB_COMPONENT(load_path);
			
			//jscrlpne = new JScrollPane(component, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);			
			//this.add(BorderLayout.CENTER, jscrlpne);
			
			this.add(BorderLayout.CENTER, component);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
}
